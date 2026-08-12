#!/usr/bin/env python3
"""CERT r4.2 dataset exploration.

Loads each of the five CERT Insider Threat CSVs (logon, device, file, email,
http) from data/raw/ with pandas and prints:
  - row counts
  - column names
  - dtypes
  - 3 sample rows
  - (if data/raw/answers/ or a labels file is present) the count of
    insider-threat-labeled users from the answer key

Usage:
    python3 scripts/explore_cert.py          # explore all 5 CSVs
    python3 scripts/explore_cert.py logon    # explore only logon.csv
"""
import os
import sys
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = REPO_ROOT / "data" / "raw"
# Official CMU archives extract straight into data/raw/, while some mirrors
# (e.g., the Kaggle upload) nest the CSVs under a r4.2/ subdirectory.
KAGGLE_NEST = DATA_RAW / "r4.2"
ANSWERS_DIR = DATA_RAW / "answers"

CSV_FILES = ["logon.csv", "device.csv", "file.csv", "email.csv", "http.csv"]

# NOTE: columns below reflect the *measured* Kaggle-mirror schema
# (id, date, user, pc, ...) -- see docs/cert_dataset_notes.md.
BEHAVIOR_COLUMNS = {
    "logon.csv": ["user", "pc", "date", "activity"],
    "device.csv": ["user", "pc", "date", "activity"],
    "file.csv": ["user", "pc", "date", "filename", "content"],
    "email.csv": ["user", "pc", "to", "cc", "bcc", "from", "date", "size", "attachments", "content"],
    "http.csv": ["user", "pc", "date", "url", "content"],
}


def _load_answers_user_count() -> int | None:
    """Count unique insider-threat-labeled users from the answer key, if present.

    The CERT answer key is a tar.bz2 archive containing one .answers file per
    dataset (e.g., logon.answers). Each answer row encodes the malicious actor's
    user id via the 'uid' field in the scenario description; we extract the
    labeled user ids by scanning every text answer file.
    """
    if not ANSWERS_DIR.is_dir():
        return None

    labeled_users = set()
    answer_files = sorted(ANSWERS_DIR.glob("*.answers"))
    if not answer_files:
        # Maybe the archive was extracted to a different folder layout
        answer_files = sorted(ANSWERS_DIR.rglob("*.answers"))
    for path in answer_files:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("scenario"):
                    continue
                # Answer rows are comma-separated; the uid is conventionally
                # placed in a quoted string field. A robust heuristic: pull
                # every token that looks like a CERT user id (single letter +
                # digits, e.g. CDE0182).
                import re
                for token in re.findall(r"\b[A-Z]{3}\d{4}\b", line):
                    labeled_users.add(token)
    return len(labeled_users) if labeled_users else None


def explore(csv_name: str) -> None:
    path = DATA_RAW / csv_name
    if not path.exists() and KAGGLE_NEST.exists():
        path = KAGGLE_NEST / csv_name
    print("=" * 70)
    print(f"FILE: {csv_name} ({path})")
    if not path.exists():
        print(f"  !! NOT FOUND -- expected at {path}")
        return

    # http.csv is ~14.5 GB and email.csv ~1.3 GB -- always read a small chunk
    # for metadata, and only load fully when the file is modest in size.
    header = pd.read_csv(path, nrows=0)
    chunk = pd.read_csv(path, nrows=3)
    print(f"  columns   : {list(header.columns)}")
    print("  dtypes    :")
    for col, dtype in header.dtypes.items():
        print(f"    {col:<12} {dtype}")
    if path.stat().st_size < 500_000_000:
        df = pd.read_csv(path)
        print(f"  rows      : {len(df):,}")
    else:
        print(f"  size      : {path.stat().st_size / 1073741824:.2f} GB (huge -- row count skipped)")
    print("  sample rows:")
    print(chunk.to_string(index=False))
    print("=" * 70)
    print()


def main() -> int:
    wanted = sys.argv[1:] if len(sys.argv) > 1 else CSV_FILES
    wanted = [w if w.endswith(".csv") else w + ".csv" for w in wanted]
    wanted = [w for w in wanted if w in CSV_FILES]

    if not DATA_RAW.exists():
        print(f"ERROR: {DATA_RAW} does not exist. Download the CERT r4.2 CSVs first.")
        print("See scripts/fetch_cert_data.py for a helper.")
        return 1

    missing = [c for c in wanted if not ((DATA_RAW / c).exists() or (KAGGLE_NEST / c).exists())]
    if missing:
        print(f"WARNING: missing CSVs (will skip): {missing}\n")

    for csv_name in wanted:
        if (DATA_RAW / csv_name).exists() or (KAGGLE_NEST / csv_name).exists():
            explore(csv_name)

    print("=" * 70)
    count = _load_answers_user_count()
    if count is not None:
        print(f"INSIDER-THREAT-LABELED USERS (from answers/): {count}")
    else:
        print("answers/ directory not found -- skipping insider-label count.")
        print("(Run scripts/fetch_cert_data.py to download the answer key too.)")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
