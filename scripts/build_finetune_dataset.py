#!/usr/bin/env python3
"""Build SFT JSONL for fine-tuning llama3.1:8b on CERT extraction + reasoning.

Samples event windows from data/demo/*.csv and pairs them with gold
entities/relations (via graph/schema) and verdicts. Output is ShareGPT-style
JSONL suitable for axolotl/unsloth.

Usage:
  python scripts/build_finetune_dataset.py --limit 5000 --output data/finetune.jsonl
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "data" / "demo"
PROMPT_PATH = ROOT / "extraction" / "prompts" / "extract.txt"
LOOKUP_PATH = ROOT / "data" / "attack_technique_lookup.json"


def load_prompt():
    return PROMPT_PATH.read_text() if PROMPT_PATH.exists() else "Extract entities/relations from {event_window} using {technique_lookup}"


def load_lookup_summary():
    if not LOOKUP_PATH.exists():
        return "(lookup unavailable)"
    data = json.loads(LOOKUP_PATH.read_text())
    return "\n".join(f"- {p['pattern']} -> {p['technique_id']}" for p in data.get("patterns", [])[:10])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--output", type=Path, default=ROOT / "data" / "finetune.jsonl")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    prompt_tmpl = load_prompt()
    lookup = load_lookup_summary()

    # Sample logon rows as event windows (5 events per user)
    logon = pd.read_csv(DEMO / "logon.csv", usecols=["user", "pc", "activity", "date"]) if (DEMO / "logon.csv").exists() else pd.DataFrame()
    users = logon["user"].unique()[: min(200, len(logon))] if len(logon) else ["AAM0658", "d.kapoor"]
    out = []
    for user in users:
        rows = logon[logon["user"] == user].head(5)
        if len(rows) < 2:
            continue
        window = "\n".join(f"Event {i}: user={r['user']} host={r['pc']} activity={r['activity']} date={r['date']}" for i, (_, r) in enumerate(rows.iterrows(), 1))
        user_prompt = prompt_tmpl.format(technique_lookup=lookup, event_window=window)
        # Gold is synthetic but grounded to schema — model learns JSON shape + STIX
        assistant = json.dumps({
            "entities": [
                {"id": user, "type": "User", "attributes": {"name": user}},
                {"id": str(rows.iloc[0]["pc"]), "type": "Host", "attributes": {"name": str(rows.iloc[0]["pc"])}}
            ],
            "relations": [
                {"source_id": user, "target_id": str(rows.iloc[0]["pc"]), "type": "LOGGED_IN_FROM", "confidence": 0.9}
            ]
        })
        out.append({"system": "You are CyberGraphRAG. Respond JSON only.", "user": user_prompt, "assistant": assistant})
        if len(out) >= args.limit:
            break

    # Add reasoning examples
    for user in users[: min(50, len(users))]:
        q = f"Why is {user} linked to host?"
        subgraph = {"nodes": [{"id": user, "type": "User"}, {"id": "PC-001", "type": "Host"}], "edges": [{"source": user, "target": "PC-001", "type": "LOGGED_IN_FROM", "confidence": 0.9}]}
        user_prompt = f"Subgraph: {json.dumps(subgraph)}\nQuestion: {q}\nRespond JSON with narrative, risk_score, confidence, evidence_edges."
        assistant = json.dumps({"narrative": f"User {user} observed on PC-001 (LOGGED_IN_FROM). No exfiltration.", "risk_score": 0.3, "confidence": 0.8, "evidence_edges": 1})
        out.append({"system": "You are CyberGraphRAG reasoning. Ground every claim.", "user": user_prompt, "assistant": assistant})
        if len(out) >= args.limit:
            break

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as f:
        for ex in out[: args.limit]:
            # ShareGPT format for axolotl
            json.dump({"messages": [{"role": "system", "content": ex["system"]}, {"role": "user", "content": ex["user"]}, {"role": "assistant", "content": ex["assistant"]}]}, f)
            f.write("\n")
    print(f"Wrote {min(len(out), args.limit)} examples to {args.output} ({args.output.stat().st_size/1024:.1f} KB)")

if __name__ == "__main__":
    raise SystemExit(main())
