#!/usr/bin/env python3
"""Week 4 — scripts/run_extraction_sample.py

Runs the real entity extractor end-to-end on 5 sample events pulled from the
demo dataset (the first 5 events of one user, spanning logon/device/file/
email/http). With a configured API key it prints the extracted entities and
relations to the console for eyeballing.

Usage:
    python3 scripts/run_extraction_sample.py            # uses env LLM_PROVIDER/key
    python3 scripts/run_extraction_sample.py --user CTR0341

Requires: LLM_PROVIDER + matching API key in .env (see .env.example).
"""
import csv
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from ingestion.log_parser import parse_row, LogType  # noqa: E402

DEMO_DIR = REPO_ROOT / "data" / "demo"

LOG_FILES = {
    LogType.LOGON: "logon.csv",
    LogType.DEVICE: "device.csv",
    LogType.FILE: "file.csv",
    LogType.EMAIL: "email.csv",
    LogType.HTTP: "http.csv",
}


def first_events_for_user(user: str, per_type: int = 1):
    events = []
    for log_type, fname in LOG_FILES.items():
        path = DEMO_DIR / fname
        if not path.exists():
            print(f"  !! {fname} missing -- build the demo dataset first")
            continue
        with path.open(encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            count = 0
            for row in reader:
                if row.get("user") == user:
                    try:
                        events.append(parse_row(log_type, dict(row)))
                    except ValueError:
                        pass  # skip malformed rows
                    count += 1
                    if count >= per_type:
                        break
    # sort chronologically
    events.sort(key=lambda e: e.timestamp)
    return events


def main() -> int:
    user = "CTR0341"
    if "--user" in sys.argv:
        user = sys.argv[sys.argv.index("--user") + 1]

    print(f"Pulling sample events for user {user} ...")
    events = first_events_for_user(user)
    if not events:
        print("No events found for that user in the demo dataset.")
        return 1
    print(f"  {len(events)} events loaded:")
    for e in events[:8]:
        print(f"    {e.event_type.value:<6} {e.timestamp} {e.host}")

    print("\nCalling LLM extractor (needs LLM_PROVIDER + API key in .env) ...")
    try:
        from llm.client import LLMClient
        from extraction.entity_extractor import extract

        client = LLMClient()
        print(f"  provider={client.provider!r} model={client.model!r}")
        entities, relations = extract(client, events)
    except Exception as exc:  # noqa: BLE001
        print(f"  !! Extraction failed: {type(exc).__name__}: {exc}")
        print("     Set LLM_PROVIDER and the matching API key in .env and retry.")
        return 1

    print(f"\nExtracted {len(entities)} entities and {len(relations)} relations:")
    for ent in entities:
        print(f"  ENTITY  {ent.id:<38} {ent.type:<18} conf={ent.confidence}")
    for rel in relations:
        print(f"  REL     {rel.source_id} --[{rel.type}]--> {rel.target_id}  conf={rel.confidence}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
