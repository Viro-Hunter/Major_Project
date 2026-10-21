#!/usr/bin/env python3
"""Week 10 — run the full pipeline over a labelled test set and compute all five metrics.

    python evaluation/run_benchmark.py                   # auto: real answer key if present, else injected scenarios
    python evaluation/run_benchmark.py --users 100 --insiders 20
    python evaluation/run_benchmark.py --llm             # verdicts from the configured LLM (slow; default is offline template)

Outputs (evaluation/results/):
    benchmark_report.md   formatted tables for the report
    benchmark.json        every number in machine-readable form (read by the dashboard MetricsPanel)
    timings.csv           indexing + per-query timings
    per_user.csv          one row per user: label, scenario, risk, confidence, verdict, groundedness
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RESULTS = ROOT / "evaluation" / "results"
DETECTION_THRESHOLD = 0.4  # == verdict_label "suspicious" boundary (reasoning/confidence_scoring.py)


def _r(x: float, n: int = 3) -> float:
    return round(float(x), n)


def run(args) -> dict:
    os.environ["CYBERGRAPHRAG_OFFLINE"] = "0" if args.llm else "1"
    tag = f"_{args.tag}" if getattr(args, "tag", "") else ""
    extractor = getattr(args, "extractor", "rules")
    sleep_s = float(getattr(args, "sleep", 0.0) or 0.0)
    # fault injection triggers the checker's warnings on purpose; keep the console readable
    logging.getLogger("reasoning.groundedness_checker").setLevel(logging.CRITICAL)
    from evaluation import metrics as M
    from evaluation.scenarios import SCENARIO_TEXT, build_labelled_set, story_entity_ids
    from ingestion.cert_loader import data_source
    from scripts.build_graph_from_cert import build_graph_from_rows
    from retrieval.router import classify_query
    from retrieval.graph_retriever import retrieve_subgraph
    from reasoning.verdict_generator import CONTEXT_KEY, generate_verdict
    from reasoning.groundedness_checker import check_groundedness
    from reasoning.confidence_scoring import attach_confidence
    from reasoning.evidence import behavioral_risk, technique_prevalence

    print(f"[1/6] building labelled set (mode={args.mode}) ...", flush=True)
    ls = build_labelled_set(args.mode, n_users=args.users, n_insiders=args.insiders,
                            rows_per_user=args.rows_per_user, seed=args.seed)
    timer = M.ResponseTimer()

    print("[2/6] indexing (extraction + graph build) ...", flush=True)
    enrichment = None
    with timer.measure("indexing", f"{sum(map(len, ls.rows_by_log.values()))} rows"):
        store = build_graph_from_rows(ls.rows_by_log, labeled_users={u for u, y in ls.labels.items() if y})
        if extractor == "hybrid":
            from extraction.llm_enrichment import enrich_with_llm
            from llm.client import LLMClient

            print("      hybrid extraction: LLM enrichment of event windows ...", flush=True)
            enrichment = enrich_with_llm(store, ls.rows_by_log, LLMClient(), windows_per_user=1).as_dict()
    g = store.graph

    # Metric 2: graph completeness against ids derived independently from the raw rows
    expected_ids = set(ls.labels)
    for name, rows in ls.rows_by_log.items():
        for row in rows:
            expected_ids |= story_entity_ids(name, row)
    completeness = M.graph_completeness(store, expected_entities=expected_ids)

    prevalence = technique_prevalence(g)
    question_tmpl = "Is {user} exfiltrating data or behaving like an insider threat?"
    per_user = []
    fault_rng = random.Random(args.seed + 7)
    fault = {"clean_verdicts": 0, "clean_false_alarms": 0, "injected": 0, "caught": 0,
             "recovered_by_retry": 0, "flagged_unverified": 0, "retries": 0}

    print(f"[3/6] querying {len(ls.labels)} users ...", flush=True)
    for i, user in enumerate(sorted(ls.labels)):
        if sleep_s and i:
            import time as _time

            _time.sleep(sleep_s)  # stay under free-model rate limits
        q = question_tmpl.format(user=user)
        with timer.measure("query_total", user):
            route = classify_query(q)
            hops = 2 if route in ("structural", "hybrid") else 1
            with timer.measure("retrieval", user):
                retrieve_subgraph(user, q, store, max_hops=hops)
                sg = store.get_subgraph_dict(user, hops=hops)
            sg[CONTEXT_KEY] = {"focus": user, "prevalence": prevalence}
            with timer.measure("reasoning", user):
                verdict = generate_verdict(sg, q)
            with timer.measure("groundedness", user):
                verdict = check_groundedness(verdict, sg, regenerate=lambda s, a, i: generate_verdict(s, q, extra_instruction=i))
            verdict = attach_confidence(verdict, sg, user)
        status = verdict["groundedness"]["status"]
        fault["clean_verdicts"] += 1
        fault["clean_false_alarms"] += status == "unverified"

        # Groundedness fault-injection (Week 8 novelty): simulate a hallucinating LLM.
        # With prob p the first verdict cites a fabricated edge id; each regeneration is
        # still hallucinated with prob p_retry. Measures catch / recovery / flag rates.
        if fault_rng.random() < args.hallucination_rate:
            fault["injected"] += 1
            bad = dict(verdict, cited_edges=list(verdict.get("cited_edges", [])) + [f"fabricated-{user}"])
            outcomes = iter([fault_rng.random() < args.retry_failure_rate for _ in range(3)])

            def regen(s, a, i, _v=verdict, _u=user):
                return dict(_v, cited_edges=list(_v.get("cited_edges", [])) + [f"fabricated2-{_u}"]) if next(outcomes) else dict(_v)

            checked = check_groundedness(bad, sg, regenerate=regen)
            gs = checked["groundedness"]
            fault["caught"] += gs["status"] != "grounded"
            fault["recovered_by_retry"] += gs["status"] == "regenerated"
            fault["flagged_unverified"] += gs["status"] == "unverified"
            fault["retries"] += gs["retries_used"]

        ablate_no_peer = behavioral_risk(sg, user, None)["risk"]
        any_technique = bool(behavioral_risk(sg, user, None)["techniques"])
        sg.pop(CONTEXT_KEY, None)
        per_user.append({
            "user": user, "label": ls.labels[user], "scenario": ls.scenario_of.get(user, ""),
            "risk": float(verdict.get("risk_score", 0.0)), "verdict_label": verdict.get("verdict_label"),
            "confidence_pct": verdict.get("confidence_pct"), "groundedness": status, "model": verdict.get("model"),
            "evidence_entities": verdict.get("evidence_entities", []),
            "evidence_techniques": verdict.get("evidence_techniques", []),
            "risk_no_peer_baseline": ablate_no_peer, "any_technique": any_technique,
        })

    print("[4/6] computing metrics ...", flush=True)
    labels = {r["user"]: r["label"] for r in per_user}
    flagged = {r["user"]: r["risk"] >= DETECTION_THRESHOLD for r in per_user}

    # Metric 5: detection effectiveness (+ ablation and naive baseline, same threshold)
    detection = M.threat_detection_effectiveness(flagged, labels)
    abl = M.threat_detection_effectiveness({r["user"]: r["risk_no_peer_baseline"] >= DETECTION_THRESHOLD for r in per_user}, labels)
    naive = M.threat_detection_effectiveness({r["user"]: r["any_technique"] for r in per_user}, labels)
    sweep = []
    for t in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7):
        d = M.threat_detection_effectiveness({r["user"]: r["risk"] >= t for r in per_user}, labels)
        sweep.append({"threshold": t, **{k: d[k] for k in ("precision", "recall", "f1", "fpr", "tp", "fp")}})
    by_scenario = {}
    for scn in sorted({r["scenario"] for r in per_user if r["label"]}):
        rows = [r for r in per_user if r["scenario"] == scn]
        by_scenario[scn] = {"insiders": len(rows), "detected": sum(flagged[r["user"]] for r in rows),
                            "mean_risk": _r(sum(r["risk"] for r in rows) / len(rows)),
                            "description": SCENARIO_TEXT.get(scn, "")}
    benign_risks = [r["risk"] for r in per_user if not r["label"]]

    # Metric 1: retrieval accuracy over insiders (evidence entities vs entities of malicious events)
    per_insider = [M.retrieval_accuracy(r["evidence_entities"], ls.truth_entities.get(r["user"], set()))
                   for r in per_user if r["label"]]
    retrieval = M.macro_average(per_insider)

    # Metric 3: threat-correlation precision on (user, ATT&CK technique) links asserted for flagged users
    predicted_pairs = {(r["user"], t) for r in per_user if flagged[r["user"]] for t in r["evidence_techniques"]}
    correlation = M.threat_correlation_precision(predicted_pairs, ls.truth_pairs)
    truth_tech = Counter(t.split(":")[-1] for _, t in ls.truth_pairs)
    hit_tech = Counter(t.split(":")[-1] for _, t in predicted_pairs & ls.truth_pairs)

    # Metric 4: response time
    times = timer.summary()
    RESULTS.mkdir(parents=True, exist_ok=True)
    timer.write_csv(RESULTS / f"timings{tag}.csv")

    groundedness_live = Counter(r["groundedness"] for r in per_user)
    models = Counter(r["model"] for r in per_user)
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
        "label_mode": ls.mode, "data_source": data_source(), "notes": ls.notes,
        "models": dict(models), "detection_threshold": DETECTION_THRESHOLD,
        "extractor": extractor, "llm_enrichment": enrichment,
        "dataset": {"users": len(labels), "insiders": sum(labels.values()), "benign": len(labels) - sum(labels.values()),
                    "rows": {k: len(v) for k, v in ls.rows_by_log.items()}, "malicious_rows": len(ls.malicious_ids),
                    "graph_nodes": g.number_of_nodes(), "graph_edges": g.number_of_edges()},
        "headline": {
            "retrieval_accuracy_f1": _r(retrieval["f1"]),
            "graph_completeness": _r(completeness["ratio"]),
            "threat_correlation_precision": _r(correlation["precision"]),
            "mean_query_latency_s": _r(times["query_total"]["mean_s"], 4),
            "indexing_time_s": _r(times["indexing"]["total_s"], 3),
            "detection_f1": _r(detection["f1"]),
            "detection_precision": _r(detection["precision"]),
            "detection_recall": _r(detection["recall"]),
            "false_positive_rate": _r(detection["fpr"]),
        },
        "retrieval_accuracy": {k: _r(v) for k, v in retrieval.items()},
        "graph_completeness": {k: v for k, v in completeness.items() if k != "missing"} | {"missing_sample": completeness["missing"][:10]},
        "threat_correlation": {k: (_r(v) if isinstance(v, float) else v) for k, v in correlation.items()},
        "technique_coverage": {t: {"expected": truth_tech[t], "found": hit_tech[t]} for t in sorted(truth_tech)},
        "response_time": {k: {kk: _r(vv, 5) for kk, vv in v.items()} for k, v in times.items()},
        "detection": {k: (_r(v) if isinstance(v, float) else v) for k, v in detection.items()},
        "detection_ablation_no_peer_baseline": {k: (_r(v) if isinstance(v, float) else v) for k, v in abl.items()},
        "detection_naive_any_technique": {k: (_r(v) if isinstance(v, float) else v) for k, v in naive.items()},
        "threshold_sweep": [{k: (_r(v) if isinstance(v, float) else v) for k, v in s.items()} for s in sweep],
        "by_scenario": by_scenario,
        "benign_risk": {"mean": _r(sum(benign_risks) / max(len(benign_risks), 1)), "max": _r(max(benign_risks, default=0))},
        "groundedness_live": dict(groundedness_live),
        "groundedness_fault_injection": fault | {
            "hallucination_rate": args.hallucination_rate, "retry_failure_rate": args.retry_failure_rate,
            "catch_rate": _r(fault["caught"] / fault["injected"]) if fault["injected"] else None,
            "false_alarm_rate": _r(fault["clean_false_alarms"] / fault["clean_verdicts"]) if fault["clean_verdicts"] else None,
        },
    }
    with (RESULTS / f"per_user{tag}.csv").open("w", newline="") as fh:
        cols = ["user", "label", "scenario", "risk", "verdict_label", "confidence_pct", "groundedness", "model",
                "risk_no_peer_baseline", "any_technique", "evidence_techniques"]
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in per_user:
            w.writerow({**r, "risk": f"{r['risk']:.4f}", "risk_no_peer_baseline": f"{r['risk_no_peer_baseline']:.4f}",
                        "evidence_techniques": " ".join(t.split(':')[-1] for t in r["evidence_techniques"])})
    print("[5/6] writing report ...", flush=True)
    (RESULTS / f"benchmark{tag}.json").write_text(json.dumps(result, indent=2, default=str))
    (RESULTS / f"benchmark_report{tag}.md").write_text(render_markdown(result))
    print(f"[6/6] done -> {RESULTS / f'benchmark_report{tag}.md'}", flush=True)
    return result


def _pct(x) -> str:
    return "—" if x is None else f"{100 * float(x):.1f}%"


def render_markdown(r: dict) -> str:
    h, d, ds = r["headline"], r["detection"], r["dataset"]
    lines = [
        "# Benchmark Report — Cyber Intelligence GraphRAG",
        "",
        f"_Generated {r['generated_at']} by `evaluation/run_benchmark.py` — do not edit by hand; re-run the script._",
        "",
        "## Setup",
        "",
        f"- **Ground truth:** `{r['label_mode']}` — " + "; ".join(r["notes"]),
        f"- **Log data:** `{r['data_source']}` CERT r4.2 ({'committed demo subset' if r['data_source'] == 'demo' else 'full dataset'}), "
        f"{ds['users']} users ({ds['insiders']} insiders / {ds['benign']} benign), "
        f"{sum(ds['rows'].values()):,} log rows ({ds['malicious_rows']} malicious)",
        f"- **Graph:** {ds['graph_nodes']:,} nodes, {ds['graph_edges']:,} edges",
        f"- **Verdict model:** " + ", ".join(f"`{m}` ×{n}" for m, n in r["models"].items()),
        f"- **Extraction:** `{r.get('extractor', 'rules')}`" + (f" — LLM enrichment {r['llm_enrichment']}" if r.get("llm_enrichment") else ""),
        f"- **Detection rule:** user flagged when checked risk ≥ {r['detection_threshold']} (the `suspicious` verdict boundary); seed {r['config']['seed']}",
        "",
        "## Table 1 — Headline metrics",
        "",
        "| Metric | Value | Definition |",
        "|---|---|---|",
        f"| Retrieval accuracy (F1) | {h['retrieval_accuracy_f1']:.3f} | Macro-F1 of entities on verified evidence paths vs entities of each insider's malicious events |",
        f"| Graph completeness | {_pct(h['graph_completeness'])} | Entities in graph / entities derivable from the ingested log rows |",
        f"| Threat-correlation precision | {h['threat_correlation_precision']:.3f} | Share of asserted (user → ATT&CK technique) links that are true malicious links |",
        f"| Response time | {h['indexing_time_s']:.2f} s indexing · {1000 * h['mean_query_latency_s']:.0f} ms/query | Graph build once; mean end-to-end query (retrieve → verdict → groundedness → confidence) |",
        f"| Detection effectiveness | P {d['precision']:.3f} · R {d['recall']:.3f} · F1 {d['f1']:.3f} · FPR {d['fpr']:.3f} | Per-user insider detection vs labels |",
        "",
        "## Table 2 — Detection: full system vs ablation vs naive baseline",
        "",
        "| Variant | Precision | Recall | F1 | FPR | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, key in (("Full system (peer baseline + confidence propagation)", "detection"),
                      ("Ablation: no peer-prevalence discount", "detection_ablation_no_peer_baseline"),
                      ("Naive baseline: any ATT&CK match ⇒ insider", "detection_naive_any_technique")):
        x = r[key]
        lines.append(f"| {name} | {x['precision']:.3f} | {x['recall']:.3f} | {x['f1']:.3f} | {x['fpr']:.3f} | {x['tp']} | {x['fp']} | {x['fn']} | {x['tn']} |")
    lines += ["", "## Table 3 — Threshold sweep (full system)", "",
              "| Risk threshold | Precision | Recall | F1 | FPR | TP | FP |", "|---|---|---|---|---|---|---|"]
    for s in r["threshold_sweep"]:
        lines.append(f"| {s['threshold']:.1f} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | {s['fpr']:.3f} | {s['tp']} | {s['fp']} |")
    lines += ["", "## Table 4 — Detection by insider scenario", "",
              "| Scenario | Description | Insiders | Detected | Mean risk |", "|---|---|---|---|---|"]
    for scn, x in r["by_scenario"].items():
        lines.append(f"| {scn} | {x['description']} | {x['insiders']} | {x['detected']} | {x['mean_risk']:.3f} |")
    lines.append(f"| benign | unlabelled real users | {ds['benign']} | {d['fp']} flagged (FP) | {r['benign_risk']['mean']:.3f} (max {r['benign_risk']['max']:.3f}) |")
    ra, tc = r["retrieval_accuracy"], r["threat_correlation"]
    lines += ["", "## Table 5 — Retrieval and threat correlation", "",
              "| Measure | Precision | Recall | F1 |", "|---|---|---|---|",
              f"| Evidence-entity retrieval (macro over insiders) | {ra['precision']:.3f} | {ra['recall']:.3f} | {ra['f1']:.3f} |",
              f"| (user, technique) correlation | {tc['precision']:.3f} | {tc['recall']:.3f} | {tc['f1']:.3f} |",
              "", "ATT&CK coverage of malicious events (expected = hand-labelled, found = asserted by the system):", "",
              "| Technique | Expected links | Found |", "|---|---|---|"]
    for t, x in r["technique_coverage"].items():
        lines.append(f"| {t} | {x['expected']} | {x['found']} |")
    gc = r["graph_completeness"]
    lines += ["", f"Graph completeness: {gc['found']:,} of {gc['expected']:,} expected entities present."]
    lines += ["", "## Table 6 — Response time", "", "| Phase | Calls | Mean | p50 | p95 | Max |", "|---|---|---|---|---|---|"]
    for phase, x in r["response_time"].items():
        lines.append(f"| {phase} | {x['count']} | {1000 * x['mean_s']:.1f} ms | {1000 * x['p50_s']:.1f} ms | {1000 * x['p95_s']:.1f} ms | {1000 * x['max_s']:.1f} ms |")
    f = r["groundedness_fault_injection"]
    lines += ["", "## Table 7 — Groundedness self-check (core contribution)", "",
              f"Live verdicts: " + ", ".join(f"{k} ×{v}" for k, v in r["groundedness_live"].items()) + ".", "",
              f"Fault injection: a simulated hallucinating LLM appends a fabricated edge id to {_pct(f['hallucination_rate'])} of verdicts; "
              f"each regeneration is still hallucinated with probability {_pct(f['retry_failure_rate'])}.", "",
              "| Measure | Value |", "|---|---|",
              f"| Verdicts with a fabricated citation | {f['injected']} |",
              f"| Caught by the checker (catch rate) | {f['caught']} ({_pct(f['catch_rate'])}) |",
              f"| Recovered by constrained regeneration | {f['recovered_by_retry']} |",
              f"| Flagged `[unverified]` + risk downgraded 20% | {f['flagged_unverified']} |",
              f"| Total regeneration calls | {f['retries']} |",
              f"| False alarms on clean verdicts | {f['clean_false_alarms']} of {f['clean_verdicts']} ({_pct(f['false_alarm_rate'])}) |",
              "", "## Threats to validity", "",
              "- With `injected` ground truth the insider behaviour is synthetic (modelled on the published CERT r4.2 scenarios) and the "
              "\"benign\" users are unlabelled real users, a few of whom may be genuine insiders. Re-run after "
              "`python scripts/fetch_cert_data.py answers` to evaluate against the official answer key.",
              "- In offline mode verdicts come from the deterministic evidence template, which is grounded by construction; "
              "the fault-injection table is what exercises the groundedness checker. Re-run with `--llm` to measure a real model.",
              "- The detection threshold is the fixed verdict boundary, not tuned on this data; Table 3 shows the trade-off.",
              ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["auto", "real", "injected"], default="auto")
    ap.add_argument("--users", type=int, default=60)
    ap.add_argument("--insiders", type=int, default=12)
    ap.add_argument("--rows-per-user", type=int, default=60)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--llm", action="store_true", help="verdicts from the configured model (.env / OPENROUTER_*)")
    ap.add_argument("--extractor", choices=["rules", "hybrid"], default="rules", help="hybrid = rules + LLM enrichment")
    ap.add_argument("--tag", default="", help="suffix for output files, e.g. llm -> benchmark_llm.json")
    ap.add_argument("--sleep", type=float, default=0.0, help="seconds between queries (free models are rate-limited)")
    ap.add_argument("--hallucination-rate", type=float, default=0.3)
    ap.add_argument("--retry-failure-rate", type=float, default=0.5)
    args = ap.parse_args()
    r = run(args)
    print(json.dumps(r["headline"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
