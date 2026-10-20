"""Labelled test sets for the benchmark.

Two sources of ground truth, chosen automatically:

REAL   — the official CERT r4.2 answer key in data/raw/answers/ (download with
         ``python scripts/fetch_cert_data.py answers``).  Insider users and their
         malicious event rows come straight from the key.

INJECTED (default when no key is present) — the committed demo subset has no
         labels, so seeded insider scenarios are injected into the real traces of
         randomly chosen demo users.  The scenarios paraphrase the three insider
         scenarios published in the CERT r4.2 dataset readme:

           S1  after-hours logins + removable media + upload to WikiLeaks
           S2  job-site browsing, then data theft over a thumb drive
           S3  disgruntled admin: keylogger download, supervisor-PC login after
               hours, mass email to external recipients

         The ground-truth ATT&CK technique for every injected event is written by
         hand below (EXPECTED column), NOT computed with the detector's own
         heuristics.  Some events intentionally map to techniques the lookup table
         cannot produce (e.g. T1056 Input Capture for a keylogger, T1567 for a
         WikiLeaks upload whose URL does not contain "upload"), so the benchmark
         measures real coverage gaps rather than echoing the rules back.

CAVEAT  r4.2 contains ~70 real insiders among 1000 users; the "benign" demo users
        are unlabelled real users, so a few may be genuine (unlabelled) insiders.
        Use the REAL mode for numbers you put in a paper.
"""
from __future__ import annotations

import csv
import io
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
ANSWERS_DIR = ROOT / "data" / "raw" / "answers"
INTERNAL_DOMAIN = "dtaa.com"
COLUMNS = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "http": ["id", "date", "user", "pc", "url", "content"],
}
EVENT_ID_RE = re.compile(r"\{[A-Z0-9]{4}-[A-Z0-9]{8}-[A-Z0-9]{8}\}")
USER_RE = re.compile(r"\b[A-Z]{3}\d{4}\b")


@dataclass
class LabelledSet:
    mode: str                                   # "real" | "injected"
    rows_by_log: dict[str, list[dict[str, Any]]]
    labels: dict[str, bool]                     # user -> is insider
    scenario_of: dict[str, str] = field(default_factory=dict)
    truth_entities: dict[str, set[str]] = field(default_factory=dict)   # user -> entity ids from malicious rows
    truth_pairs: set[tuple[str, str]] = field(default_factory=set)      # (user, "attack:Txxxx")
    malicious_ids: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Entity ids — same convention as scripts/build_graph_from_cert.ingest_row
# --------------------------------------------------------------------------- #
def story_entity_ids(name: str, row: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    host = str(row.get("pc", ""))
    if not host:
        return ids
    ids.add(f"host:{host}")
    if name == "file" and str(row.get("filename", "")).strip():
        ids.add(f"file:{str(row['filename']).strip()}")
    elif name == "device":
        ids.add(f"device:{row.get('id', '') or host + ':' + row.get('activity', '')}")
    elif name == "email":
        ids.add(f"email:{row.get('id')}")
    elif name == "http" and str(row.get("url", "")).strip():
        ids.add(f"net:{str(row['url']).strip()[:60]}")
    return ids


def expected_techniques_for_real_row(name: str, row: dict[str, Any]) -> set[str]:
    """Hand mapping (log type -> ATT&CK) for answer-key rows; independent of the detector heuristics."""
    activity = str(row.get("activity", "")).lower()
    if name == "logon" and activity == "logon":
        return {"T1078"}
    if name == "device" and activity == "connect":
        return {"T1052"}
    if name == "file":
        return {"T1005"}
    if name == "email":
        recips = ";".join(str(row.get(k, "")) for k in ("to", "cc", "bcc")).lower()
        return {"T1048"} if any("@" in a and not a.endswith(INTERNAL_DOMAIN) for a in re.split(r"[;\s]+", recips)) else set()
    if name == "http":
        return {"T1567"}
    return set()


# --------------------------------------------------------------------------- #
# REAL mode
# --------------------------------------------------------------------------- #
def answers_available(answers_dir: Path = ANSWERS_DIR) -> bool:
    return answers_dir.exists() and any(answers_dir.rglob("*"))


def load_answer_key(answers_dir: Path = ANSWERS_DIR, dataset: str = "4.2") -> dict[str, Any]:
    """Parse the CERT answer key: insider users + malicious rows (as dicts with ``_log``)."""
    insiders: set[str] = set()
    scenario_of: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for path in sorted(answers_dir.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(errors="ignore")
        if path.name.lower() == "insiders.csv":
            for rec in csv.DictReader(io.StringIO(text)):
                if str(rec.get("dataset", "")).strip() in (dataset, f"r{dataset}"):
                    user = str(rec.get("user", "")).strip()
                    if user:
                        insiders.add(user)
                        scenario_of[user] = f"S{rec.get('scenario', '?')}"
            continue
        if f"r{dataset}" not in str(path) and "answers" != path.suffix.lstrip("."):
            continue
        for line in csv.reader(io.StringIO(text)):
            if not line or line[0].strip().lower() not in COLUMNS:
                continue
            name = line[0].strip().lower()
            values = line[1:]
            row = dict(zip(COLUMNS[name], values))
            if len(values) > len(COLUMNS[name]):  # content may contain commas
                row[COLUMNS[name][-1]] = ",".join(values[len(COLUMNS[name]) - 1:])
            row["_log"] = name
            rows.append(row)
            if row.get("user"):
                insiders.add(row["user"])
    return {"insiders": insiders, "scenario_of": scenario_of, "rows": rows}


def build_real_set(n_benign: int, rows_per_user: int, seed: int, max_insiders: int = 30) -> LabelledSet:
    from ingestion.cert_loader import list_users, load_rows

    key = load_answer_key()
    present = set(list_users())
    insiders = sorted(key["insiders"] & present)
    rng = random.Random(seed)
    insiders = sorted(rng.sample(insiders, min(max_insiders, len(insiders))))
    benign_pool = sorted(present - key["insiders"])
    benign = sorted(rng.sample(benign_pool, min(n_benign, len(benign_pool))))
    mal_rows = [r for r in key["rows"] if r.get("user") in set(insiders)]
    mal_ids = {r["id"] for r in mal_rows if r.get("id")}
    rows_by_log = load_rows(insiders + benign, rows_per_user=rows_per_user, always_include_ids=mal_ids)
    ls = LabelledSet("real", rows_by_log, {u: u in set(insiders) for u in insiders + benign},
                     scenario_of={u: key["scenario_of"].get(u, "?") for u in insiders}, malicious_ids=mal_ids)
    for r in mal_rows:
        ls.truth_entities.setdefault(r["user"], set()).update(story_entity_ids(r["_log"], r))
        for t in expected_techniques_for_real_row(r["_log"], r):
            ls.truth_pairs.add((r["user"], f"attack:{t}"))
    ls.notes.append(f"official CERT r4.2 answer key: {len(insiders)} insiders, {len(benign)} benign users")
    return ls


# --------------------------------------------------------------------------- #
# INJECTED mode
# --------------------------------------------------------------------------- #
SCENARIOS = ("S1", "S2", "S3")
SCENARIO_TEXT = {
    "S1": "after-hours logins + removable media + upload to WikiLeaks",
    "S2": "job-site browsing, then data theft over a thumb drive",
    "S3": "disgruntled admin: keylogger, supervisor-PC login after hours, mass external email",
}


def _parse(d: str) -> datetime:
    return datetime.strptime(d, "%m/%d/%Y %H:%M:%S")


def _fmt(d: datetime) -> str:
    return d.strftime("%m/%d/%Y %H:%M:%S")


def _rand_name(rng: random.Random, ext: str) -> str:
    return "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8)) + ext


def _rand_id(rng: random.Random, tag: str) -> str:
    a = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(8))
    return f"{{INJ{tag}-{a}-{rng.randrange(10**7, 10**8)}X}}"


def _scenario_events(scn: str, user: str, own_pc: str, other_pc: str, day: datetime, rng: random.Random) -> list[tuple[str, dict, set[str]]]:
    """(log, row, EXPECTED techniques) for one injected scenario instance. EXPECTED is hand-written."""
    ev: list[tuple[str, dict, set[str]]] = []
    me = f"{user.lower()}@{INTERNAL_DOMAIN}"

    def at(days: int, hh: int, mm: int) -> str:
        return _fmt(day.replace(hour=hh, minute=mm, second=rng.randrange(60)) + timedelta(days=days))

    if scn == "S1":
        for d in (0, 1):
            ev.append(("logon", {"date": at(d, 23, 5), "pc": own_pc, "activity": "Logon"}, {"T1078"}))
            ev.append(("device", {"date": at(d, 23, 20), "pc": own_pc, "activity": "Connect"}, {"T1052"}))
            for _ in range(2):
                ev.append(("file", {"date": at(d, 23, 30 + rng.randrange(20)), "pc": own_pc,
                                    "filename": _rand_name(rng, ".doc"), "content": "D0-CF-11-E0 internal draft"}, {"T1005", "T1052"}))
            ev.append(("http", {"date": at(d, 23, 55), "pc": own_pc,
                                "url": f"http://wikileaks.org/Julian_Assange/leak/submission{rng.randrange(1000)}.aspx",
                                "content": "submission form"}, {"T1567"}))
            ev.append(("device", {"date": at(d + 1, 0, 10), "pc": own_pc, "activity": "Disconnect"}, set()))
            ev.append(("logon", {"date": at(d + 1, 0, 15), "pc": own_pc, "activity": "Logoff"}, set()))
    elif scn == "S2":
        for d in range(3):
            for site in ("monster.com", "careerbuilder.com", "indeed.com"):
                ev.append(("http", {"date": at(d, 12, 10 + rng.randrange(40)), "pc": own_pc,
                                    "url": f"http://www.{site}/jobs/search{rng.randrange(10**6)}.aspx", "content": "job listings"}, set()))
        for d in (3, 4):
            ev.append(("device", {"date": at(d, 15, 2), "pc": own_pc, "activity": "Connect"}, {"T1052"}))
            for _ in range(4):
                ev.append(("file", {"date": at(d, 15, 5 + rng.randrange(40)), "pc": own_pc,
                                    "filename": _rand_name(rng, rng.choice([".doc", ".pdf", ".xls"])), "content": "project data"}, {"T1005", "T1052"}))
            ev.append(("device", {"date": at(d, 15, 50), "pc": own_pc, "activity": "Disconnect"}, set()))
    elif scn == "S3":
        ev.append(("http", {"date": at(0, 10, 15), "pc": own_pc,
                            "url": f"http://www.keylogger-tools.net/download/kl{rng.randrange(1000)}.exe", "content": "keylogger"}, {"T1056"}))
        ev.append(("device", {"date": at(0, 10, 30), "pc": own_pc, "activity": "Connect"}, {"T1052"}))
        ev.append(("file", {"date": at(0, 10, 33), "pc": own_pc, "filename": _rand_name(rng, ".exe"), "content": "MZ executable"}, {"T1056"}))
        ev.append(("device", {"date": at(0, 10, 40), "pc": own_pc, "activity": "Disconnect"}, set()))
        ev.append(("logon", {"date": at(1, 22, 40), "pc": other_pc, "activity": "Logon"}, {"T1078"}))
        ext = ";".join(f"{n}@{dom}" for n, dom in (("news.desk", "nytimes.com"), ("tips", "reuters.com"),
                                                     ("hr.alerts", "gmail.com"), ("info", "yahoo.com")))
        ev.append(("email", {"date": at(1, 22, 55), "pc": other_pc, "to": ext, "cc": "", "bcc": "",
                             "from": me, "size": "2450000", "attachments": "2", "content": "urgent company notice"},
                   {"T1048", "T1567"}))
        ev.append(("logon", {"date": at(1, 23, 10), "pc": other_pc, "activity": "Logoff"}, set()))
    return ev


def build_injected_set(n_users: int, n_insiders: int, rows_per_user: int, seed: int) -> LabelledSet:
    from ingestion.cert_loader import load_rows, sample_users

    users = sample_users(n_users, seed=seed)
    rng = random.Random(seed + 1)
    insiders = sorted(rng.sample(users, min(n_insiders, len(users))))
    rows_by_log = load_rows(users, rows_per_user=rows_per_user)

    pcs_by_user: dict[str, Counter] = defaultdict(Counter)
    dates_by_user: dict[str, list[datetime]] = defaultdict(list)
    for name, rows in rows_by_log.items():
        for r in rows:
            pcs_by_user[r["user"]][r.get("pc", "")] += 1
            try:
                dates_by_user[r["user"]].append(_parse(r["date"]))
            except (KeyError, ValueError):
                pass
    all_pcs = sorted({pc for c in pcs_by_user.values() for pc in c if pc})

    ls = LabelledSet("injected", rows_by_log, {u: u in set(insiders) for u in users})
    for i, user in enumerate(insiders):
        scn = SCENARIOS[i % len(SCENARIOS)]
        ls.scenario_of[user] = scn
        own_pc = pcs_by_user[user].most_common(1)[0][0] if pcs_by_user[user] else "PC-0000"
        others = [p for p in all_pcs if p not in pcs_by_user[user]] or ["PC-9999"]
        other_pc = rng.choice(others)
        dates = sorted(dates_by_user[user]) or [datetime(2010, 1, 4)]
        lo, hi = dates[0], dates[-1]
        # Attack inside the user's observed window (last 40%), so time-decay treats
        # injected and normal evidence alike instead of favouring the attack.
        start = lo + (hi - lo) * 0.6
        span_days = max(0, (hi - start).days - 4)
        day = (start + timedelta(days=rng.randint(0, span_days))).replace(hour=0, minute=0, second=0)
        for name, partial, expected in _scenario_events(scn, user, own_pc, other_pc, day, rng):
            row = {c: "" for c in COLUMNS[name]}
            row.update(partial)
            row["id"] = _rand_id(rng, scn)
            row["user"] = user
            rows_by_log[name].append(row)
            ls.malicious_ids.add(row["id"])
            ls.truth_entities.setdefault(user, set()).update(story_entity_ids(name, row) - {f"host:{own_pc}"})
            for t in expected:
                ls.truth_pairs.add((user, f"attack:{t}"))
    ls.notes.append(
        f"INJECTED scenarios (no answer key found in data/raw/answers): {len(insiders)} insiders "
        f"({', '.join(f'{s}={sum(1 for v in ls.scenario_of.values() if v == s)}' for s in SCENARIOS)}) "
        f"among {len(users)} real demo users; benign users are unlabelled real CERT users"
    )
    return ls


def build_labelled_set(mode: str = "auto", n_users: int = 60, n_insiders: int = 12,
                       rows_per_user: int = 60, seed: int = 42) -> LabelledSet:
    if mode == "real" or (mode == "auto" and answers_available()):
        return build_real_set(n_benign=n_users - n_insiders, rows_per_user=rows_per_user, seed=seed)
    return build_injected_set(n_users, n_insiders, rows_per_user, seed)
