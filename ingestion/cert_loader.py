"""Load CERT rows for a chosen set of users (shared by e2e, benchmark and demo scripts).

Resolution order for each log: data/raw/<log>.csv -> data/raw/r4.2/<log>.csv -> data/demo/<log>.csv
(the committed demo subset), so everything runs from a clean clone.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any, Iterable, Optional

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CSV_NAMES = ("logon", "device", "file", "email", "http")


def locate(name: str) -> Optional[Path]:
    for directory in (ROOT / "data" / "raw", ROOT / "data" / "raw" / "r4.2", ROOT / "data" / "demo"):
        path = directory / f"{name}.csv"
        if path.exists():
            return path
    return None


def data_source() -> str:
    path = locate("logon")
    if path is None:
        return "missing"
    return "demo" if path.parent.name == "demo" else "raw"


def list_users(limit_scan_rows: int = 2_000_000) -> list[str]:
    """All users seen in logon.csv (sorted, deterministic)."""
    path = locate("logon")
    if path is None:
        raise FileNotFoundError("logon.csv not found in data/raw or data/demo")
    users: set[str] = set()
    seen = 0
    for chunk in pd.read_csv(path, usecols=["user"], chunksize=200_000, dtype=str):
        users.update(chunk["user"].dropna())
        seen += len(chunk)
        if seen >= limit_scan_rows:
            break
    return sorted(users)


def sample_users(n: int, seed: int = 42, exclude: Iterable[str] = ()) -> list[str]:
    pool = [u for u in list_users() if u not in set(exclude)]
    rng = random.Random(seed)
    return sorted(rng.sample(pool, min(n, len(pool))))


def load_rows(
    users: Iterable[str],
    rows_per_user: int = 60,
    always_include_ids: Optional[set[str]] = None,
    logs: Iterable[str] = CSV_NAMES,
) -> dict[str, list[dict[str, Any]]]:
    """Up to ``rows_per_user`` earliest rows per (user, log), plus any row whose id is listed.

    ``always_include_ids`` lets the benchmark keep every answer-key (malicious) row even
    when it falls after the per-user cap.
    """
    users = set(users)
    keep_ids = always_include_ids or set()
    out: dict[str, list[dict[str, Any]]] = {}
    for name in logs:
        path = locate(name)
        if path is None:
            out[name] = []
            continue
        counts: dict[str, int] = {}
        rows: list[dict[str, Any]] = []
        for chunk in pd.read_csv(path, chunksize=100_000, dtype=str):
            chunk = chunk[chunk["user"].isin(users)].fillna("")
            for row in chunk.to_dict("records"):
                u = row["user"]
                if row.get("id") in keep_ids or counts.get(u, 0) < rows_per_user:
                    rows.append(row)
                    counts[u] = counts.get(u, 0) + 1
        out[name] = rows
    return out
