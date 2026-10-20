#!/usr/bin/env python3
"""Week 12 — live, presentation-ready walkthrough of the whole pipeline.

Seeds a synthetic insider (scenario S1: after-hours logins, USB, upload to WikiLeaks)
into real CERT activity of a few demo users, then prints each stage:

    events -> entities -> graph -> retrieval -> verdict -> groundedness check -> confidence

    python scripts/demo.py               # offline: deterministic evidence template (no model needed)
    python scripts/demo.py --llm         # use the configured model (.env: Ollama / OpenRouter / ...)
    python scripts/demo.py --pause       # wait for Enter between stages while presenting
"""
from __future__ import annotations

import argparse
import os
import random
import sys
import textwrap
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = ("\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m")
if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = CYAN = RESET = ""


def stage(n: int, title: str, pause: bool) -> None:
    if pause and n > 1:
        input(f"{DIM}  [Enter] next stage{RESET}")
    print(f"\n{BOLD}{CYAN}[{n}/7] {title}{RESET}")


def wrap(text: str, indent: str = "      ") -> str:
    return textwrap.fill(text, width=100, initial_indent=indent, subsequent_indent=indent)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--pause", action="store_true")
    ap.add_argument("--seed", type=int, default=3)
    args = ap.parse_args()
    if not args.llm:
        os.environ["CYBERGRAPHRAG_OFFLINE"] = "1"
    import logging
    logging.getLogger("reasoning.groundedness_checker").setLevel(logging.CRITICAL)  # demo shows outcomes itself

    from evaluation.scenarios import COLUMNS, _rand_id, _scenario_events, story_entity_ids
    from ingestion.cert_loader import data_source, load_rows, sample_users
    from ingestion.log_parser import LogType, parse_row
    from scripts.build_graph_from_cert import build_graph_from_rows
    from retrieval.router import classify_query
    from retrieval.graph_retriever import retrieve_subgraph
    from reasoning.verdict_generator import CONTEXT_KEY, generate_verdict
    from reasoning.groundedness_checker import check_groundedness
    from reasoning.confidence_scoring import attach_confidence
    from reasoning.evidence import technique_prevalence
    from datetime import datetime

    print(f"{BOLD}Cyber Intelligence GraphRAG — live demo{RESET}  {DIM}(data: {data_source()} CERT r4.2){RESET}")

    # 1 ------------------------------------------------------------------
    stage(1, "Events — raw CERT logs normalised into timestamped events", args.pause)
    users = sample_users(12, seed=args.seed)
    rows = load_rows(users, rows_per_user=40)
    # The quietest user (fewest USB/off-hours style events) makes the seeded attack stand out, as a real one would.
    activity = Counter(r["user"] for n in ("device", "file") for r in rows[n])
    insider = min(users, key=lambda u: (activity[u], u))
    own_pc = Counter(r["pc"] for r in rows["logon"] if r["user"] == insider).most_common(1)[0][0]
    other_pc = next(r["pc"] for r in rows["logon"] if r["pc"] != own_pc)
    dates = sorted(datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S") for n in rows for r in rows[n] if r["user"] == insider)
    day = dates[int(len(dates) * 0.7)].replace(hour=0, minute=0, second=0)
    rng = random.Random(args.seed)
    injected = []
    for name, partial, _ in _scenario_events("S1", insider, own_pc, other_pc, day, rng):
        row = {c: "" for c in COLUMNS[name]} | partial | {"id": _rand_id(rng, "S1"), "user": insider}
        rows[name].append(row)
        injected.append((name, row))
    total = sum(len(v) for v in rows.values())
    print(f"      {total:,} rows from {len(users)} real users; seeded insider scenario S1 into {BOLD}{insider}{RESET} "
          f"({len(injected)} events: after-hours logon, USB, file copies, WikiLeaks upload)")
    for name, row in injected[:5]:
        ev = parse_row(LogType(name), row)
        detail = row.get("activity") or row.get("filename") or row.get("url", "")[:50]
        print(f"      {DIM}{ev.timestamp}{RESET}  {name:<6} {ev.user} @ {ev.host}  {detail}")

    # 2-3 ----------------------------------------------------------------
    stage(2, "Entities — each event becomes a story chain User → Host → File/Device/URL → ATT&CK", args.pause)
    store = build_graph_from_rows(rows)
    ids = set().union(*(story_entity_ids(n, r) for n, r in injected))
    for i in sorted(ids)[:6]:
        print(f"      {store.graph.nodes[i].get('type', '?'):<18} {i}")
    stage(3, "Graph — NetworkX knowledge graph with ATT&CK technique nodes", args.pause)
    g = store.graph
    types = Counter(d.get("type") for _, d in g.nodes(data=True))
    print(f"      {g.number_of_nodes():,} nodes, {g.number_of_edges():,} edges  " + ", ".join(f"{t} {c}" for t, c in types.most_common()))
    techs = sorted(n for n, d in g.nodes(data=True) if d.get("type") == "AttackTechnique")
    print(f"      ATT&CK techniques present: {', '.join(t.split(':')[1] for t in techs)}")

    # 4 ------------------------------------------------------------------
    question = f"Why is {insider} linked to data exfiltration techniques?"
    stage(4, f"Retrieval — {question}", args.pause)
    route = classify_query(question)
    r = retrieve_subgraph(insider, question, store, max_hops=2 if route != "lookup" else 1)
    sg = store.get_subgraph_dict(insider, hops=1)
    print(f"      router: {BOLD}{route}{RESET} → {r['max_hops']}-hop retrieval, {r['subgraph'].number_of_nodes()} nodes; "
          f"top path confidence {r['paths'][0]['confidence']:.2f}" if r["paths"] else "      no paths")

    # 5 ------------------------------------------------------------------
    stage(5, "Verdict — model reasons over the subgraph and must cite edge ids", args.pause)
    sg[CONTEXT_KEY] = {"focus": insider, "prevalence": technique_prevalence(g)}
    verdict = generate_verdict(sg, question)
    print(f"      model: {verdict.get('model')}   risk: {verdict['risk_score']:.2f}   cited edges: {len(verdict.get('cited_edges', []))}")
    print(wrap(verdict.get("narrative", "")))

    # 6 ------------------------------------------------------------------
    stage(6, "Groundedness check — every cited edge must exist (core contribution)", args.pause)
    checked = check_groundedness(verdict, sg, regenerate=lambda s, a, i: generate_verdict(s, question, extra_instruction=i))
    gs = checked["groundedness"]
    print(f"      {GREEN}✓ {gs['status']}{RESET}: {len(gs['verified_edges'])} of {len(checked.get('cited_edges', []))} cited edges verified, retries used {gs['retries_used']}")
    fake = dict(verdict, cited_edges=list(verdict.get("cited_edges", [])) + ["e99999"], narrative=verdict.get("narrative", ""))
    caught = check_groundedness(fake, sg)  # no regenerator: shows the fail-safe path
    print(f"      {RED}✗ simulated hallucination{RESET} citing e99999 → status {BOLD}{caught['groundedness']['status']}{RESET}, "
          f"risk {fake['risk_score']:.2f} → {caught['risk_score']:.2f} (−20%), narrative tagged [unverified]")

    # 7 ------------------------------------------------------------------
    stage(7, "Confidence — propagated over verified evidence paths only (0.95/day decay)", args.pause)
    final = attach_confidence(checked, sg, insider)
    colour = RED if final["verdict_label"] == "high_risk" else YELLOW if final["verdict_label"] == "suspicious" else GREEN
    print(f"      verdict {colour}{BOLD}{final['verdict_label'].upper()}{RESET}   risk {final['risk_score']:.2f}   confidence {final['confidence_pct']:.1f}%")
    from reasoning.evidence import find_evidence_paths

    verified = set(gs["verified_edges"])
    best: dict = {}
    for p in find_evidence_paths(sg, insider):  # strongest first; prefer full story chains for display
        if set(p["edge_ids"]) <= verified and (p["technique"] not in best or (len(p["nodes"]) > len(best[p["technique"]]["nodes"]) and p["confidence"] >= 0.3)):
            best[p["technique"]] = p
    print(f"      {DIM}evidence chains (one per technique):{RESET}")
    for p in sorted(best.values(), key=lambda p: -p["confidence"])[:6]:
        chain = f" → ".join(n.split(":", 1)[-1].strip("{}")[:26] for n in p["nodes"])
        print(f"      {DIM}{p['timestamp']}{RESET}  {chain}  {DIM}({100 * p['confidence']:.0f}%, edges {', '.join(p['edge_ids'])}){RESET}")
    print(f"\n{BOLD}Done.{RESET} Dashboard: uvicorn api.main:app --port 8000  +  cd dashboard && npm run dev")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
