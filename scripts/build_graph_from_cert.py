#!/usr/bin/env python3
"""Build a small, portable graph from a CERT r4.2 subset.

The script reads only selected users and uses chunks so it remains usable with
CERT's multi-gigabyte email/http files.  If an answer key is present, its first
two labeled users are guaranteed to be included.  Without one, the documented
r4.2 fallback identifiers are included and marked ``labels_unverified``.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import pandas as pd

from graph.graph_store import GraphStore
from graph.schema import parse_event_timestamp

ROOT = Path(__file__).resolve().parents[1]
LOOKUP_PATH = ROOT / "data" / "attack_technique_lookup.json"
CSV_NAMES = ("logon", "device", "file", "email", "http")
# Used only when the answer archive is not available locally.
FALLBACK_LABELED_USERS = ("AAM0658", "CDE1846")


def locate(name: str) -> Path | None:
    for directory in (ROOT / "data" / "raw", ROOT / "data" / "raw" / "r4.2", ROOT / "data" / "demo"):
        path = directory / f"{name}.csv"
        if path.exists():
            return path
    return None


def answer_labels() -> set[str]:
    labels: set[str] = set()
    for path in (ROOT / "data" / "raw" / "answers").rglob("*.answers") if (ROOT / "data" / "raw" / "answers").exists() else []:
        labels.update(re.findall(r"\b[A-Z]{3}\d{4}\b", path.read_text(errors="ignore")))
    return labels


def discover_users(paths: list[Path], limit: int, labels: set[str]) -> list[str]:
    users: set[str] = set()
    for path in paths:
        for chunk in pd.read_csv(path, usecols=["user"], chunksize=50_000):
            users.update(str(user) for user in chunk["user"].dropna())
            if len(users) >= limit * 3:
                break
        if len(users) >= limit * 3:
            break
    preferred = sorted(labels & users)[:2]
    # Preserve two known labels even when the local subset has not observed them.
    if len(preferred) < 2:
        preferred = list(dict.fromkeys(preferred + list(FALLBACK_LABELED_USERS)))[:2]
    return preferred + [u for u in sorted(users) if u not in preferred][: max(0, limit - len(preferred))]


def technique_nodes(lookup: dict[str, Any]) -> dict[str, tuple[str, dict[str, Any]]]:
    result = {}
    for pattern in lookup.get("patterns", []):
        tid = pattern["technique_id"]
        result[pattern["pattern"]] = (tid, pattern)
    return result


def match_patterns(row: dict[str, Any], log_name: str, prior_files: dict[str, set[str]]) -> list[str]:
    activity = str(row.get("activity", "")).lower()
    filename = str(row.get("filename", "")).lower()
    recipients = ";".join(str(row.get(key, "")) for key in ("to", "cc", "bcc")).lower()
    external = [x for x in re.split(r"[;\s]+", recipients) if "@" in x and not x.endswith("@dtaa.com")]
    patterns: list[str] = []
    if log_name == "logon":
        try:
            hour = pd.to_datetime(row.get("date")).hour
            weekday = pd.to_datetime(row.get("date")).weekday()
            if activity == "logon" and (hour >= 22 or hour < 5 or weekday >= 5):
                patterns.append("off_hours_login")
        except (ValueError, TypeError):
            pass
    elif log_name == "device" and activity == "connect":
        patterns.append("usb_device_connect")
    elif log_name == "file":
        user = str(row.get("user", ""))
        if filename and filename not in prior_files[user]:
            patterns.append("first_time_file_access")
        prior_files[user].add(filename)
        if any(word in filename for word in ("confidential", "financial", "payroll", "classified", "report")):
            patterns.append("sensitive_file_access")
    elif log_name == "email":
        try:
            size = float(row.get("size", 0) or 0)
        except (TypeError, ValueError):
            size = 0
        try:
            attachments = int(float(row.get("attachments", 0) or 0))
        except (TypeError, ValueError):
            attachments = 0
        if attachments > 0 and external:
            patterns.append("external_email_with_attachment")
        if size > 1_000_000:
            patterns.append("large_data_transfer")
        if len(external) >= 3:
            patterns.append("email_to_many_external_recipients")
    elif log_name == "http":
        url = str(row.get("url", "")).lower()
        if any(host in url for host in ("drive.google", "dropbox", "mega.nz", "wetransfer", "upload")):
            patterns.append("suspicious_web_traffic")
            patterns.append("large_data_transfer")
    return patterns


def build_graph(user_limit: int = 20, rows_per_user: int = 25) -> GraphStore:
    lookup = json.loads(LOOKUP_PATH.read_text())
    paths = [path for name in CSV_NAMES if (path := locate(name))]
    labels = answer_labels()
    users = discover_users(paths, user_limit, labels)
    store = GraphStore()
    labeled = set(labels) if labels else set(FALLBACK_LABELED_USERS)
    for user in users:
        store.add_entity({"id": user, "type": "User", "attributes": {"insider_threat_label": user in labeled, "labels_verified": bool(labels)}})

    counts: defaultdict[str, int] = defaultdict(int)
    prior_files: defaultdict[str, set[str]] = defaultdict(set)
    techniques = technique_nodes(lookup)
    for name in CSV_NAMES:
        path = locate(name)
        if not path:
            continue
        for chunk in pd.read_csv(path, chunksize=20_000, dtype=str):
            chunk = chunk.fillna("")
            for row in chunk.to_dict("records"):
                user = str(row.get("user", ""))
                if user not in users or counts[user] >= rows_per_user:
                    continue
                host = str(row.get("pc", ""))
                if not host:
                    continue
                host_id = f"host:{host}"
                store.add_entity({"id": host_id, "type": "Host", "attributes": {"name": host}})
                timestamp = parse_event_timestamp(str(row.get("date", "")))
                store.add_relation(user, host_id, "OBSERVED_ON", 0.9, timestamp, source=name)
                for pattern in match_patterns(row, name, prior_files):
                    tid, detail = techniques[pattern]
                    technique_id = f"attack:{tid}"
                    store.add_entity({"id": technique_id, "type": "AttackTechnique", "attributes": detail})
                    store.add_relation(user, technique_id, "MATCHES_TECHNIQUE", 0.75, timestamp, pattern=pattern, source=name)
                counts[user] += 1
            if all(counts[u] >= rows_per_user for u in users):
                break
    return store


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--rows-per-user", type=int, default=25)
    parser.add_argument("--output", type=Path, default=ROOT / "data" / "cert_graph.json")
    args = parser.parse_args()
    graph = build_graph(args.users, args.rows_per_user)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(graph.to_json())
    print(f"wrote {args.output} ({graph.graph.number_of_nodes()} nodes, {graph.graph.number_of_edges()} edges)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
