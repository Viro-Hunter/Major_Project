#!/usr/bin/env python3
"""Week 9 — run the full pipeline end to end on a CERT subset.

    ingestion -> extraction -> graph -> retrieval -> reasoning -> groundedness -> confidence

Every stage is timed and wrapped so a failure is logged with its stage name
instead of crashing the run.  Exit code is 0 only if every stage succeeded for
every user, so this doubles as an integration smoke test.

    python scripts/run_pipeline_e2e.py                      # 20 users, offline-safe
    python scripts/run_pipeline_e2e.py --users 40 --llm     # use the configured LLM (Ollama/Claude)
    python scripts/run_pipeline_e2e.py --llm-extract        # also run LLM entity extraction on a 5-event window

Writes a JSON summary to evaluation/results/e2e_run.json.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import traceback
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

log = logging.getLogger("e2e")


class Stage:
    """Context manager that times a stage and records failures without stopping the run."""

    def __init__(self, report: dict, name: str, user: str | None = None):
        self.report, self.name, self.user = report, name, user

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb):
        dt = time.perf_counter() - self.t0
        self.report["timings"][self.name].append(dt)
        if exc is not None:
            where = f"{self.name}" + (f" [{self.user}]" if self.user else "")
            log.error("stage %s failed: %s", where, exc)
            self.report["errors"].append({"stage": self.name, "user": self.user, "error": repr(exc),
                                          "traceback": traceback.format_exc(limit=4)})
            return True  # swallow: keep the run going, the error is recorded
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--users", type=int, default=20)
    ap.add_argument("--rows-per-user", type=int, default=60)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--llm", action="store_true", help="use the configured LLM for verdicts (default: offline template)")
    ap.add_argument("--llm-extract", action="store_true", help="also run LLM entity extraction on one 5-event window")
    ap.add_argument("--question", default="Is this user exfiltrating data or behaving like an insider threat?")
    ap.add_argument("--output", type=Path, default=ROOT / "evaluation" / "results" / "e2e_run.json")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    if not args.llm:
        os.environ["CYBERGRAPHRAG_OFFLINE"] = "1"

    from ingestion.cert_loader import data_source, load_rows, sample_users
    from ingestion.log_parser import LogType, parse_row
    from scripts.build_graph_from_cert import build_graph_from_rows
    from retrieval.router import classify_query
    from retrieval.graph_retriever import retrieve_subgraph
    from reasoning.verdict_generator import CONTEXT_KEY, generate_verdict
    from reasoning.groundedness_checker import check_groundedness
    from reasoning.confidence_scoring import attach_confidence
    from reasoning.evidence import technique_prevalence

    report: dict = {"timings": defaultdict(list), "errors": [], "config": vars(args) | {"output": str(args.output)},
                    "data_source": data_source(), "results": []}
    rows_by_log: dict = {}
    store = None

    # 1. Ingestion -------------------------------------------------------------
    with Stage(report, "ingestion"):
        users = sample_users(args.users, seed=args.seed)
        rows_by_log = load_rows(users, rows_per_user=args.rows_per_user)
        parsed, bad = 0, 0
        for name, rows in rows_by_log.items():
            for row in rows:
                try:
                    parse_row(LogType(name), row)
                    parsed += 1
                except Exception:
                    bad += 1
        report["ingestion"] = {"users": len(users), "rows": {k: len(v) for k, v in rows_by_log.items()},
                               "normalized_events": parsed, "rejected_rows": bad}
        log.info("ingestion: %d users, %d rows normalized (%d rejected) from %s data",
                 len(users), parsed, bad, report["data_source"])

    # 2. Extraction (+ optional LLM extraction sample) -------------------------
    if args.llm_extract:
        with Stage(report, "extraction_llm_sample"):
            from extraction.entity_extractor import extract
            from llm.client import LLMClient
            window = [parse_row(LogType(n), r) for n in ("logon", "device", "file") for r in rows_by_log.get(n, [])[:2]][:5]
            ents, rels = extract(LLMClient(), window)
            report["extraction_llm_sample"] = {"entities": len(ents), "relations": len(rels)}
            log.info("LLM extraction sample: %d entities, %d relations", len(ents), len(rels))

    # 3. Graph -----------------------------------------------------------------
    with Stage(report, "extraction+graph"):
        store = build_graph_from_rows(rows_by_log)
        g = store.graph
        report["graph"] = {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
                           "node_types": dict(Counter(d.get("type") for _, d in g.nodes(data=True))),
                           "edge_types": dict(Counter(d.get("type") for *_, d in g.edges(data=True)))}
        log.info("graph: %d nodes, %d edges", g.number_of_nodes(), g.number_of_edges())

    if store is None:
        log.error("graph stage failed; cannot continue")
        return _finish(report, args.output)

    prevalence = technique_prevalence(store.graph)
    route = classify_query(args.question)
    hops = 2 if route in ("structural", "hybrid") else 1

    for user in sorted(n for n, d in store.graph.nodes(data=True) if d.get("type") == "User"):
        rec: dict = {"user": user}
        ok = True
        # 4. Retrieval
        with Stage(report, "retrieval", user) as st:
            r = retrieve_subgraph(user, args.question, store, max_hops=hops)
            sg = store.get_subgraph_dict(user, hops=hops)
            rec["retrieval"] = {"route": route, "nodes": len(sg["nodes"]), "edges": len(sg["edges"]),
                                "top_path_confidence": r["paths"][0]["confidence"] if r["paths"] else None}
        ok = ok and "retrieval" in rec
        if not ok:
            report["results"].append(rec)
            continue
        sg[CONTEXT_KEY] = {"focus": user, "prevalence": prevalence}
        # 5. Reasoning
        with Stage(report, "reasoning", user):
            verdict = generate_verdict(sg, args.question)
            rec["model"] = verdict.get("model")
        # 6. Groundedness
        with Stage(report, "groundedness", user):
            verdict = check_groundedness(verdict, sg, regenerate=lambda s, a, i: generate_verdict(s, args.question, extra_instruction=i))
            rec["groundedness"] = verdict["groundedness"]["status"]
        # 7. Confidence
        with Stage(report, "confidence", user):
            verdict = attach_confidence(verdict, sg, user)
            rec.update(risk_score=verdict.get("risk_score"), verdict_label=verdict.get("verdict_label"),
                       confidence_pct=verdict.get("confidence_pct"),
                       techniques=[c["technique_id"] for c in verdict.get("techniques", [])])
        report["results"].append(rec)
        log.info("%-8s %-10s risk=%.3f conf=%5.1f%% grounded=%s", user, rec.get("verdict_label"),
                 rec.get("risk_score") or 0, rec.get("confidence_pct") or 0, rec.get("groundedness"))

    return _finish(report, args.output)


def _finish(report: dict, output: Path) -> int:
    report["timings_summary"] = {k: {"calls": len(v), "total_s": round(sum(v), 4), "mean_s": round(sum(v) / len(v), 5)}
                                 for k, v in report["timings"].items() if v}
    report["timings"] = {k: [round(x, 5) for x in v] for k, v in report["timings"].items()}
    labels = Counter(r.get("verdict_label") for r in report["results"])
    grounded = Counter(r.get("groundedness") for r in report["results"])
    report["summary"] = {"users_processed": len(report["results"]), "verdict_labels": dict(labels),
                         "groundedness": dict(grounded), "errors": len(report["errors"])}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, default=str))
    print("\n=== E2E SUMMARY ===")
    for k, v in report["timings_summary"].items():
        print(f"  {k:<24} calls={v['calls']:<4} total={v['total_s']:.3f}s mean={v['mean_s']:.4f}s")
    print(f"  verdicts: {dict(labels)}  groundedness: {dict(grounded)}")
    print(f"  errors: {len(report['errors'])}  ->  {output}")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
