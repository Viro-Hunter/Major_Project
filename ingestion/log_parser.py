"""Week 3 — ingestion/log_parser.py

Normalizes one row from each CERT r4.2 CSV into a uniform ``Event`` object:

    Event(user, timestamp, event_type, raw_fields, event_id)

Schema note: the repo's data mirror uses the columns documented in
``docs/cert_dataset_notes.md`` (``id, date, user, pc, activity, ...``). If the
official CMU release is swapped in later, only the per-logtype parsers below
need updating.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from graph.schema import parse_event_timestamp


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
