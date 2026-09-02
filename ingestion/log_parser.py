"""Week 3 — ingestion/log_parser.py

Normalizes one row from each CERT r4.2 CSV into a uniform ``Event`` object:

    Event(user, timestamp, event_type, raw_fields, event_id)

Schema note: the repo's data mirror uses the columns documented in
``docs/cert_dataset_notes.md`` (``id, date, user, pc, activity, ...``). If the
official CMU release is swapped in later, only the per-logtype parsers below
need updating.
"""
from __future__ import annotations

import csv
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, List

import pandas as pd
from pydantic import BaseModel, Field

from graph.schema import parse_event_timestamp

# Also support advanced pipeline's schemas.Event for parse_cert_log
try:
    from ingestion.schemas import Event as AdvancedEvent
except ImportError:
    AdvancedEvent = None


class LogType(str, Enum):
    LOGON = "logon"
    DEVICE = "device"
    FILE = "file"
    EMAIL = "email"
    HTTP = "http"


class Event(BaseModel):
    """Normalized security event, the uniform currency of the pipeline."""

    user: str
    timestamp: str  # ISO-8601
    event_type: LogType
    raw_fields: dict[str, Any] = Field(default_factory=dict)
    event_id: Optional[str] = None

    @property
    def host(self) -> str:
        return self.raw_fields.get("pc", "")

    @property
    def activity(self) -> str:
        return self.raw_fields.get("activity", "")


def _require(row: dict[str, Any], *keys: str) -> None:
    missing = [k for k in keys if row.get(k) in (None, "")]
    if missing:
        raise ValueError(f"row missing required columns: {missing}")


def parse_logon_row(row: dict[str, Any]) -> Event:
    """One row of logon.csv -> Event(user logged on/off of a workstation)."""
    _require(row, "user", "pc", "activity", "date")
    return Event(
        user=str(row["user"]),
        timestamp=parse_event_timestamp(str(row["date"])),
        event_type=LogType.LOGON,
        raw_fields={"pc": str(row["pc"]), "activity": str(row["activity"])},
        event_id=str(row.get("id", "")),
    )


def parse_device_row(row: dict[str, Any]) -> Event:
    """One row of device.csv -> Event(USB/removable device connect/disconnect)."""
    _require(row, "user", "pc", "activity", "date")
    return Event(
        user=str(row["user"]),
        timestamp=parse_event_timestamp(str(row["date"])),
        event_type=LogType.DEVICE,
        raw_fields={"pc": str(row["pc"]), "activity": str(row["activity"])},
        event_id=str(row.get("id", "")),
    )


def parse_file_row(row: dict[str, Any]) -> Event:
    """One row of file.csv -> Event(file handled by a user on a workstation)."""
    _require(row, "user", "pc", "filename", "date")
    return Event(
        user=str(row["user"]),
        timestamp=parse_event_timestamp(str(row["date"])),
        event_type=LogType.FILE,
        raw_fields={
            "pc": str(row["pc"]),
            "filename": str(row["filename"]),
            "content_preview": str(row.get("content", ""))[:120],
        },
        event_id=str(row.get("id", "")),
    )


def _split_addresses(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    return [a.strip() for a in str(value).split(";") if a.strip()]


def parse_email_row(row: dict[str, Any]) -> Event:
    """One row of email.csv -> Event(email sent/received, with recipients)."""
    _require(row, "user", "pc", "date")
    return Event(
        user=str(row["user"]),
        timestamp=parse_event_timestamp(str(row["date"])),
        event_type=LogType.EMAIL,
        raw_fields={
            "pc": str(row["pc"]),
            "to": _split_addresses(row.get("to")),
            "cc": _split_addresses(row.get("cc")),
            "bcc": _split_addresses(row.get("bcc")),
            "from": str(row.get("from", "")),
            "size": int(float(row["size"])) if row.get("size") not in (None, "") else 0,
            "attachments": int(float(row["attachments"])) if row.get("attachments") not in (None, "") else 0,
            "content_preview": str(row.get("content", ""))[:120],
        },
        event_id=str(row.get("id", "")),
    )


def parse_http_row(row: dict[str, Any]) -> Event:
    """One row of http.csv -> Event(URL visited by a user on a workstation)."""
    _require(row, "user", "pc", "url", "date")
    return Event(
        user=str(row["user"]),
        timestamp=parse_event_timestamp(str(row["date"])),
        event_type=LogType.HTTP,
        raw_fields={"pc": str(row["pc"]), "url": str(row["url"]), "content_preview": str(row.get("content", ""))[:120]},
        event_id=str(row.get("id", "")),
    )


PARSERS = {
    LogType.LOGON: parse_logon_row,
    LogType.DEVICE: parse_device_row,
    LogType.FILE: parse_file_row,
    LogType.EMAIL: parse_email_row,
    LogType.HTTP: parse_http_row,
}


def parse_row(log_type: LogType, row: dict[str, Any]) -> Event:
    """Dispatch a raw CSV row dict to the right per-logtype parser."""
    if log_type not in PARSERS:
        raise ValueError(f"unknown log type: {log_type}")
    return PARSERS[log_type](row)


# ---------------------------------------------------------------------------
# Advanced pipeline helpers (merged from local stash) — keep for dashboard API
# ---------------------------------------------------------------------------

def _parse_ts(val: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M", "%m/%d/%Y %H:%M"):
        try:
            return datetime.strptime(str(val).strip(), fmt)
        except Exception:
            continue
    try:
        return pd.to_datetime(val).to_pydatetime()
    except Exception:
        return datetime.utcnow()


def parse_cert_log(path: str) -> List[Any]:
    """Advanced helper: parse CERT csv with pandas into AdvancedEvent (ingestion.schemas.Event)."""
    if AdvancedEvent is None:
        raise ImportError("ingestion.schemas not available")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    try:
        df = pd.read_csv(p, nrows=100000)
    except Exception:
        df = pd.read_csv(p, engine="python", on_bad_lines="skip")
    df.columns = [c.strip().lower() for c in df.columns]
    events: List[Any] = []
    for idx, row in df.iterrows():
        rd = {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}
        user = str(rd.get("user") or rd.get("user_id") or rd.get("employee") or rd.get("from") or "unknown").strip()
        if user == "None":
            user = "unknown"
        action = str(rd.get("activity") or rd.get("action") or rd.get("operation") or rd.get("event") or "unknown").strip()
        ts_raw = rd.get("date") or rd.get("timestamp") or rd.get("time") or rd.get("datetime") or datetime.utcnow().isoformat()
        ts = _parse_ts(str(ts_raw))

        def clean(v):
            if v is None or (isinstance(v, float) and pd.isna(v)):
                return None
            s = str(v).strip()
            if s == "" or s.lower() == "nan" or s == "None":
                return None
            return s

        target = clean(rd.get("target") or rd.get("filename") or rd.get("file") or rd.get("to") or rd.get("url"))
        host = clean(rd.get("pc") or rd.get("host") or rd.get("machine"))
        src_ip = clean(rd.get("src_ip") or rd.get("ip"))
        events.append(
            AdvancedEvent(
                event_id=str(rd.get("id") or uuid.uuid4()),
                timestamp=ts,
                user_id=user,
                action=action,
                target=target,
                host=host,
                src_ip=src_ip,
                dst_ip=clean(rd.get("dst_ip")),
                details=(str(rd.get("details") or rd.get("content") or "")[:500] or None) if clean(rd.get("details") or rd.get("content")) else None,
                raw={k: str(v) for k, v in rd.items() if v is not None},
            )
        )
    return events


def parse_json_logs(path: str) -> List[Any]:
    import json

    if AdvancedEvent is None:
        raise ImportError("ingestion.schemas not available")
    p = Path(path)
    data = json.loads(p.read_text())
    if isinstance(data, dict):
        data = [data]
    events = []
    for item in data:
        events.append(
            AdvancedEvent(
                event_id=str(item.get("event_id") or uuid.uuid4()),
                timestamp=_parse_ts(str(item.get("timestamp") or datetime.utcnow().isoformat())),
                user_id=str(item.get("user_id") or item.get("user") or "unknown"),
                action=str(item.get("action") or "unknown"),
                target=item.get("target"),
                host=item.get("host"),
                src_ip=item.get("src_ip"),
                raw=item,
            )
        )
    return events
