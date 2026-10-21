#!/usr/bin/env python3
"""Generate the data behind the dashboard's Story mode (dashboard/#story) from a REAL pipeline run.

    python scripts/build_story.py        # writes dashboard/public/story_data.json + story_stix_bundle.json

Same insider and seed as scripts/demo.py, so the terminal demo and the story tell the same case.
Every number shown in Story mode comes from this file; nothing in the page is hard-coded except prose.
"""
from __future__ import annotations

import json
import logging
import os
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "dashboard" / "public"

PLAIN = {  # ATT&CK technique -> what a non-specialist should read
    "T1078": ("Logged in outside working hours", "Valid Accounts"),
    "T1052": ("Plugged in a USB storage device", "Exfiltration Over Physical Medium"),
    "T1005": ("Opened files they had never touched before", "Data from Local System"),
    "T1567": ("Emailed attachments outside the company", "Exfiltration Over Web Service"),
    "T1048": ("Emailed many outside addresses at once", "Exfiltration Over Alternative Protocol"),
    "T1030": ("Moved an unusually large amount of data", "Data Transfer Size Limits"),
    "T1071": ("Used an upload or file-sharing website", "Application Layer Protocol"),
    "T1213": ("Pulled documents from shared repositories", "Data from Information Repositories"),
    "T1056": ("Captured other people's keystrokes", "Input Capture"),
}
KIND = {"logon": "login", "device": "USB", "file": "file", "email": "email", "http": "web"}


def describe(name: str, row: dict) -> str:
    t = datetime.strptime(row["date"], "%m/%d/%Y %H:%M:%S").strftime("%-I:%M %p")
    if name == "logon":
        return f"{t} — {'logged in to' if row.get('activity') == 'Logon' else 'logged off'} {row['pc']}"
    if name == "device":
        return f"{t} — USB drive {'plugged in' if row.get('activity') == 'Connect' else 'removed'}"
    if name == "file":
        return f"{t} — opened file {row.get('filename')}"
    if name == "http":
        host = row.get("url", "").split("/")[2] if "://" in row.get("url", "") else row.get("url", "")
        return f"{t} — visited {host}"
    if name == "email":
        return f"{t} — sent an email to {len(str(row.get('to', '')).split(';'))} recipient(s)"
    return t


def main(seed: int = 3) -> int:
    os.environ["CYBERGRAPHRAG_OFFLINE"] = "1"
    logging.getLogger("reasoning.groundedness_checker").setLevel(logging.CRITICAL)
    from evaluation.scenarios import COLUMNS, _rand_id, _scenario_events
    from ingestion.cert_loader import load_rows, sample_users
    from scripts.build_graph_from_cert import build_graph_from_rows
    from reasoning.verdict_generator import CONTEXT_KEY, generate_verdict
    from reasoning.groundedness_checker import check_groundedness
    from reasoning.confidence_scoring import attach_confidence
    from reasoning.evidence import technique_prevalence, find_evidence_paths
    from intel.stix_export import build_stix_bundle

    # same case as scripts/demo.py
    users = sample_users(12, seed=seed)
    rows = load_rows(users, rows_per_user=40)
    activity = Counter(r["user"] for n in ("device", "file") for r in rows[n])
    insider = min(users, key=lambda u: (activity[u], u))
    own_pc = Counter(r["pc"] for r in rows["logon"] if r["user"] == insider).most_common(1)[0][0]
    other_pc = next(r["pc"] for r in rows["logon"] if r["pc"] != own_pc)
    dates = sorted(datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S") for n in rows for r in rows[n] if r["user"] == insider)
    day = dates[int(len(dates) * 0.7)].replace(hour=0, minute=0, second=0)
    rng = random.Random(seed)
    injected_ids = set()
    for name, partial, _ in _scenario_events("S1", insider, own_pc, other_pc, day, rng):
        row = {c: "" for c in COLUMNS[name]} | partial | {"id": _rand_id(rng, "S1"), "user": insider}
        rows[name].append(row)
        injected_ids.add(row["id"])

    store = build_graph_from_rows(rows)
    g = store.graph
    prev = technique_prevalence(g)
    sg = store.get_subgraph_dict(insider, hops=1)
    sg[CONTEXT_KEY] = {"focus": insider, "prevalence": prev}
    q = f"Is {insider} taking company data?"
    verdict = generate_verdict(sg, q)
    checked = check_groundedness(verdict, sg, regenerate=lambda s, a, i: generate_verdict(s, q, extra_instruction=i))
    final = attach_confidence(checked, sg, insider)
    fake = dict(verdict, cited_edges=list(verdict["cited_edges"]) + ["e99999"])
    caught = check_groundedness(fake, sg)  # no regenerator: shows the fail-safe outcome

    # ---- timeline: per-day activity, attack night in detail ----
    per_day: dict[str, dict] = defaultdict(lambda: {"normal": 0, "night": 0, "attack": 0})
    night_events = []
    for name, rs in rows.items():
        for r in rs:
            if r["user"] != insider:
                continue
            t = datetime.strptime(r["date"], "%m/%d/%Y %H:%M:%S")
            d = per_day[t.strftime("%Y-%m-%d")]
            if r["id"] in injected_ids:
                d["attack"] += 1
                night_events.append({"time": t.isoformat(), "kind": KIND[name], "text": describe(name, r)})
            elif t.hour >= 20 or t.hour < 6:
                d["night"] += 1
            else:
                d["normal"] += 1
    night_events.sort(key=lambda e: e["time"])

    # ---- evidence graph (verified paths, one best chain per technique + rule edges) ----
    verified = set(checked["groundedness"]["verified_edges"])
    nodes_by_id = {n["id"]: n for n in sg["nodes"]}
    paths = [p for p in find_evidence_paths(sg, insider) if set(p["edge_ids"]) <= verified]
    best: dict = {}
    for p in paths:
        t = p["technique_id"]
        if t not in best or len(p["nodes"]) > len(best[t]["nodes"]):
            best[t] = p
    gnodes, gedges = {insider: {"id": insider, "label": insider, "kind": "person"}}, []
    for t, p in best.items():
        for a, b, rel in zip(p["nodes"], p["nodes"][1:], p["relations"]):
            kind = nodes_by_id.get(b, {}).get("type", "")
            attrs = nodes_by_id.get(b, {}).get("attributes") or {}
            raw = b.split(":", 1)[-1].strip("{}")
            label = {"AttackTechnique": PLAIN.get(raw, (raw,))[0], "Device": "USB drive", "Host": f"Computer {raw}",
                     "FileResource": f"File {raw[:18]}",
                     "EmailEvent": f"Email to {len(str(attrs.get('to', '')).split(';'))} outside address(es)",
                     "NetworkConnection": (raw.split('/')[2] if '://' in raw else raw)[:22]}.get(kind, raw[:22])
            gnodes.setdefault(b, {"id": b, "label": label, "kind": {"AttackTechnique": "technique", "Host": "computer",
                                  "Device": "usb", "FileResource": "file", "EmailEvent": "email",
                                  "NetworkConnection": "web"}.get(kind, "other"),
                                  "attack_id": b.split(":")[-1] if kind == "AttackTechnique" else None})
            gedges.append({"source": a, "target": b, "relation": rel.replace("_", " ").lower(), "edge_id": p["edge_ids"][p["relations"].index(rel)]})
    # layered layout: person | evidence | technique
    cols = {"person": [], "mid": [], "technique": []}
    for n in gnodes.values():
        cols["person" if n["kind"] == "person" else "technique" if n["kind"] == "technique" else "mid"].append(n)
    for ci, (col, ns) in enumerate(cols.items()):
        for i, n in enumerate(sorted(ns, key=lambda n: n["label"])):
            n["x"] = [90, 400, 720][ci]
            n["y"] = round(50 + (i + 0.5) * (360 / max(len(ns), 1)))

    # ---- fact-check claims (one per technique, with its log evidence) ----
    claims = []
    for t, p in sorted(best.items(), key=lambda kv: kv[1]["timestamp"]):
        ts = datetime.fromisoformat(p["timestamp"])
        claims.append({"technique": t, "text": f"{PLAIN.get(t, (t,))[0]} — {ts.strftime('%-d %b %Y, %-I:%M %p')}",
                       "edge_ids": p["edge_ids"], "verified": True, "confidence": p["confidence"],
                       "attack_name": PLAIN.get(t, ("", t))[1]})
    claims.append({"technique": None, "text": "Copied the payroll spreadsheet to a personal Dropbox account",
                   "edge_ids": ["e99999"], "verified": False, "confidence": 0.0, "attack_name": "(invented by the model)"})

    techniques_seen = {c["technique_id"]: c for c in final.get("techniques", [])} if final.get("techniques") else {}
    peers = sorted(({"technique": t.split(":")[-1], "label": PLAIN.get(t.split(":")[-1], (t,))[0],
                     "share": round(v, 3), "insider": t.split(":")[-1] in best}
                    for t, v in prev.items()), key=lambda r: r["share"])

    bench_path = ROOT / "evaluation" / "results" / "benchmark.json"
    bench = json.loads(bench_path.read_text()) if bench_path.exists() else None
    bundle = build_stix_bundle(final, sg, insider)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "story_stix_bundle.json").write_text(json.dumps(bundle, indent=2))
    sg.pop(CONTEXT_KEY, None)

    story = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "case": {"user": insider, "pc": own_pc, "colleagues": len(users) - 1, "attack_date": (lambda a, b: a.strftime("%-d %B %Y") if a.date() == b.date() else f"{a.strftime('%-d')}–{b.strftime('%-d %B %Y')}")(
                     # count by "night of" (events before 6 AM belong to the previous evening)
                     datetime.fromisoformat(night_events[0]["time"]) - timedelta(hours=6),
                     datetime.fromisoformat(night_events[-1]["time"]) - timedelta(hours=6))},
        "scale": {"employees": len(users), "events": sum(len(v) for v in rows.values()),
                  "events_insider": sum(1 for v in rows.values() for r in v if r["user"] == insider),
                  "graph_nodes": g.number_of_nodes(), "graph_edges": g.number_of_edges(),
                  "days": len(per_day), "by_kind": {KIND[k]: len(v) for k, v in rows.items()}},
        "timeline": [{"date": d, **v} for d, v in sorted(per_day.items())],
        "night_events": night_events,
        "graph": {"nodes": list(gnodes.values()), "edges": gedges},
        "peers": peers,
        "verdict": {"question": q, "narrative": final["narrative"], "risk": final["risk_score"],
                    "label": final["verdict_label"], "confidence_pct": final["confidence_pct"],
                    "cited": len(checked["cited_edges"]), "verified": len(verified),
                    "techniques": [{"id": c["technique_id"], "plain": PLAIN.get(c["technique_id"], ("",))[0],
                                    "peer_share": c["peer_prevalence"], "contribution": c["contribution"]}
                                   for c in final.get("techniques", [])]},
        "claims": claims,
        "hallucination": {"status": caught["groundedness"]["status"], "risk_before": verdict["risk_score"],
                          "risk_after": caught["risk_score"], "missing": caught["groundedness"]["missing_edges"]},
        "decay": [{"days": d, "weight": round(0.95 ** d, 3)} for d in (0, 1, 3, 7, 14, 30, 60)],
        "stix": {"objects": dict(Counter(o["type"] for o in bundle["objects"])), "total": len(bundle["objects"]),
                 "attack_ids": sorted({next(r["external_id"] for r in o["external_references"] if r.get("source_name") == "mitre-attack")
                                       for o in bundle["objects"] if o["type"] == "attack-pattern"})},
        "benchmark": None if bench is None else {
            "label_mode": bench["label_mode"], "users": bench["dataset"]["users"], "insiders": bench["dataset"]["insiders"],
            "detected": bench["detection"]["tp"], "missed": bench["detection"]["fn"],
            "false_alarms": bench["detection"]["fp"], "benign": bench["dataset"]["benign"],
            "fpr": bench["detection"]["fpr"], "fpr_no_peer": bench["detection_ablation_no_peer_baseline"]["fpr"],
            "fpr_naive": bench["detection_naive_any_technique"]["fpr"], "f1": bench["detection"]["f1"],
            "precision": bench["detection"]["precision"], "recall": bench["detection"]["recall"],
            "query_ms": round(1000 * bench["headline"]["mean_query_latency_s"], 1),
            "completeness": bench["headline"]["graph_completeness"],
            "by_scenario": {k: {"detected": v["detected"], "insiders": v["insiders"], "description": v["description"]}
                            for k, v in bench.get("by_scenario", {}).items()},
            "fault": {k: bench["groundedness_fault_injection"][k] for k in ("injected", "caught", "recovered_by_retry", "flagged_unverified", "clean_false_alarms", "clean_verdicts")},
        },
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "story_data.json").write_text(json.dumps(story, indent=2, default=str))
    print(f"story for {insider}: {len(night_events)} attack events, {len(gnodes)} graph nodes, {len(claims)} claims, "
          f"STIX {len(bundle['objects'])} objects -> {OUT.relative_to(ROOT)}/story_data.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
