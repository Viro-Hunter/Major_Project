#!/usr/bin/env python3
"""Build a small demo subset of the CERT r4.2 dataset.

Picks a fixed set of users (deterministic, reproducible) and streams their
rows out of each raw CSV into data/demo/. Keeps logon/device/file in full-ish
proportions and trims the two huge logs (email, http) to the selected users
plus a uniform small random sample of others so general graph structure is
still visible in visualizations.

Strategy and resulting size targets (full mirror in data/raw/r4.2/):
    logon.csv  ~58 MB -> all rows of chosen users (~200 users) ~ 15 MB
    device.csv ~29 MB -> same user filter                 ~ 10 MB
    file.csv   ~193MB -> same user filter                 ~ 50 MB
    email.csv  ~1.36GB -> chosen users (capped) + ~0.5% of others   ~ 40 MB
    http.csv   ~14.5GB -> chosen users (capped) + ~0.05% of others   ~ 80 MB
    Total ~ 160 MB -- every file stays under GitHub's 100 MB per-file limit,
    so the demo set can be committed to the repo directly.

The chosen-user list is derived from logon.csv by sampling user ids with a
fixed seed, so re-running this script always produces the same subset.

Usage:
    python3 scripts/build_demo_dataset.py          # build data/demo/
    python3 scripts/build_demo_dataset.py --seed 7 # different seed -> different users
"""
import hashlib
import os
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = REPO_ROOT / "data" / "raw" / "r4.2"
DEMO_DIR = REPO_ROOT / "data" / "demo"

# Files under ~500 MB are small enough to load via pandas directly; the two
# huge ones are handled line-by-line with the csv module.
SMALL_CSVS = ["logon.csv", "device.csv", "file.csv"]
BIG_CSVS = ["email.csv", "http.csv"]

N_USERS = 200            # chosen "core" users kept at 100%
BIG_SAMPLE_FRAC = {      # fraction of remaining rows kept from non-core users
    "email.csv": 0.005,  # ~0.5%  -> ~13k extra rows (~400MB -> ~25MB... kept generous)
    "http.csv": 0.0005,  # ~0.05% -> ~14k extra rows (~700MB)
}
SEED = 42

CHUNK = 100_000
CORE_ROWS_CAP = {   # per-core-user row caps in the huge logs to bound demo size
    "email.csv": 200,
    "http.csv": 400,
}


def pick_core_users(seed: int) -> set[str]:
    """Deterministically pick N_USERS from logon.csv."""
    rng = random.Random(seed)
    users = set()
    for chunk in __import__("pandas").read_csv(RAW_DIR / "logon.csv", usecols=["user"], chunksize=CHUNK):
        users.update(chunk["user"].unique())
    chosen = rng.sample(sorted(users), N_USERS)
    return set(chosen)


def stream_csv_rows(path: Path):
    """Yield (header, row_string) tuples for a huge CSV, line by line."""
    import csv

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        # Build a user-index if `user` is present (it is in all five CERT logs)
        user_idx = header.index("user")
        for row in reader:
            if len(row) > user_idx:
                yield header, row, row[user_idx]


def build_small(csv_name: str, core_users: set[str]) -> int:
    import pandas as pd

    src = RAW_DIR / csv_name
    dst = DEMO_DIR / csv_name
    dst.parent.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(src)
    kept = df[df["user"].isin(core_users)]
    kept.to_csv(dst, index=False)
    return len(kept)


def build_big(csv_name: str, core_users: set[str], rng: random.Random) -> int:
    """Stream the huge CSV; keep a bounded slice of core users + a small
    hash-sample of others so the demo stays under the size budget."""
    import csv

    src = RAW_DIR / csv_name
    dst = DEMO_DIR / csv_name
    dst.parent.mkdir(parents=True, exist_ok=True)
    frac = BIG_SAMPLE_FRAC[csv_name]
    per_user_cap = CORE_ROWS_CAP.get(csv_name)
    kept = 0
    per_user_seen = {}
    with src.open("r", encoding="utf-8", errors="replace") as fin, dst.open("w", newline="", encoding="utf-8") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        header = next(reader)
        writer.writerow(header)
        user_idx = header.index("user")
        for row in reader:
            if len(row) <= user_idx:
                continue
            user = row[user_idx]
            if user in core_users:
                if per_user_cap is None:
                    keep = True
                else:
                    per_user_seen[user] = per_user_seen.get(user, 0) + 1
                    keep = per_user_seen[user] <= per_user_cap
            else:
                # stable hash-based sampling so output is reproducible
                h = int(hashlib.sha1(f"{csv_name}:{user}".encode()).hexdigest()[:8], 16)
                keep = (h % 10_000) < int(frac * 10_000)
            if keep:
                writer.writerow(row)
                kept += 1
    return kept


def main() -> int:
    seed = SEED
    if "--seed" in sys.argv:
        seed = int(sys.argv[sys.argv.index("--seed") + 1])
    if "--clean" in sys.argv and DEMO_DIR.exists():
        for f in DEMO_DIR.glob("*.csv"):
            f.unlink()

    print(f"Building demo subset with seed={seed} ...")
    core_users = pick_core_users(seed)
    print(f"  core users chosen: {len(core_users)}")

    for csv_name in SMALL_CSVS:
        n = build_small(csv_name, core_users)
        print(f"  {csv_name:<12} -> {n:>8,} rows")
    rng = random.Random(seed)
    for csv_name in BIG_CSVS:
        n = build_big(csv_name, core_users, rng)
        print(f"  {csv_name:<12} -> {n:>8,} rows")

    total = DEMO_DIR.stat().st_size
    print(f"  total size  : {total / 1073741824:.2f} GB in {DEMO_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
