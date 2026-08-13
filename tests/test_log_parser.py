"""Week 3 — tests/test_log_parser.py

Covers one real sample row from each of the 5 CERT log types, taken from the
committed demo subset (data/demo/). Each parser must return a normalized
Event with correct user, ISO timestamp, event_type, and populated raw_fields.

Also covers the schema contracts and the ATT&CK lookup table integrity.
"""
import json
from datetime import datetime
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "data" / "demo"
DATA_DIR = REPO_ROOT / "data"

from graph.schema import (  # noqa: E402
    BaseEntity,
    ENTITY_CLASSES,
    EntityType,
    Relation,
    RelationType,
    parse_event_timestamp,
)
from ingestion.log_parser import (  # noqa: E402
    LogType,
    parse_device_row,
    parse_email_row,
    parse_file_row,
    parse_http_row,
    parse_logon_row,
    parse_row,
)


def read_first_data_row(csv_name: str) -> dict[str, str]:
    path = DEMO_DIR / csv_name
    if not path.exists():
        pytest.skip(f"demo {csv_name} missing; build the demo dataset first")
    import csv

    with path.open(encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        return dict(next(reader))


# ---------------------------------------------------------------------------
# schema sanity
# ---------------------------------------------------------------------------


def test_entity_classes_are_registered() -> None:
    from graph.schema import ENTITY_CLASSES

    for et in EntityType:
        assert et in ENTITY_CLASSES, f"{et} has no registered entity class"
        assert issubclass(ENTITY_CLASSES[et], BaseEntity)


@pytest.mark.parametrize(
    "entity_type",
    list(EntityType),
)
def test_entity_model_roundtrips(entity_type: EntityType) -> None:
    cls = ENTITY_CLASSES[entity_type]
    entity = cls(
        attributes={"key": "value"},
        confidence=0.95,
        timestamp="2010-01-02T07:14:00",
    )
    data = json.loads(entity.model_dump_json())
    assert data["type"] == entity_type.value
    assert data["confidence"] == 0.95
    assert entity.id and len(entity.id) > 0


def test_relation_model_requires_source_and_target() -> None:
    rel = Relation(
        source_id="user-1",
        target_id="host-1",
        type=RelationType.LOGGED_IN_FROM,
        confidence=0.9,
    )
    assert rel.source_id == "user-1"
    assert rel.target_id == "host-1"


def test_confidence_bounds_enforced() -> None:
    with pytest.raises(Exception):
        Relation(source_id="a", target_id="b", type=RelationType.ACCESSED, confidence=1.5)
    with pytest.raises(Exception):
        Relation(source_id="a", target_id="b", type=RelationType.ACCESSED, confidence=-0.1)


def test_parse_event_timestamp_iso() -> None:
    iso = parse_event_timestamp("01/02/2010 07:14:00")
    assert iso == datetime(2010, 1, 2, 7, 14, 0).isoformat()


def test_parse_event_timestamp_fallback() -> None:
    assert parse_event_timestamp("garbage") == "garbage"


# ---------------------------------------------------------------------------
# real sample rows from the demo dataset
# ---------------------------------------------------------------------------


class TestLogonRow:
    def test_parse(self) -> None:
        row = read_first_data_row("logon.csv")
        event = parse_logon_row(row)
        assert event.user == row["user"]
        assert event.event_type == LogType.LOGON
        assert event.host == row["pc"]
        assert event.activity == "Logon"
        assert datetime.fromisoformat(event.timestamp).year == 2010
        assert event.event_id == row["id"]

    def test_missing_column_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_logon_row({"user": "X", "pc": "PC-1"})  # missing date/activity


class TestDeviceRow:
    def test_parse(self) -> None:
        row = read_first_data_row("device.csv")
        event = parse_device_row(row)
        assert event.event_type == LogType.DEVICE
        assert event.activity == "Connect"
        assert event.host == row["pc"]


class TestFileRow:
    def test_parse(self) -> None:
        row = read_first_data_row("file.csv")
        event = parse_file_row(row)
        assert event.event_type == LogType.FILE
        assert event.raw_fields["filename"] == row["filename"]
        assert "content_preview" in event.raw_fields


class TestEmailRow:
    def test_parse(self) -> None:
        row = read_first_data_row("email.csv")
        event = parse_email_row(row)
        assert event.event_type == LogType.EMAIL
        assert isinstance(event.raw_fields["to"], list)
        assert len(event.raw_fields["to"]) >= 1
        assert isinstance(event.raw_fields["size"], int)
        assert event.raw_fields["size"] > 0

    def test_empty_recipients_become_empty_lists(self) -> None:
        row = read_first_data_row("email.csv")
        row["cc"] = row["bcc"] = ""
        event = parse_email_row(row)
        assert event.raw_fields["cc"] == []
        assert event.raw_fields["bcc"] == []


class TestHttpRow:
    def test_parse(self) -> None:
        row = read_first_data_row("http.csv")
        event = parse_http_row(row)
        assert event.event_type == LogType.HTTP
        assert str(row["url"]).startswith("http")
        assert event.raw_fields["url"] == row["url"]


class TestParseRowDispatch:
    def test_all_five_types_dispatch(self) -> None:
        mapping = {
            LogType.LOGON: "logon.csv",
            LogType.DEVICE: "device.csv",
            LogType.FILE: "file.csv",
            LogType.EMAIL: "email.csv",
            LogType.HTTP: "http.csv",
        }
        for log_type, csv in mapping.items():
            event = parse_row(log_type, read_first_data_row(csv))
            assert event.event_type == log_type

    def test_unknown_type_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_row("not_a_log", {})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ATT&CK lookup table integrity
# ---------------------------------------------------------------------------


class TestAttackTechniqueLookup:
    @pytest.fixture(autouse=True)
    def load(self) -> None:
        path = DATA_DIR / "attack_technique_lookup.json"
        if not path.exists():
            pytest.skip("attack_technique_lookup.json missing")
        with path.open() as fh:
            self.lookup = json.load(fh)

    def test_at_least_five_mapped_patterns(self) -> None:
        assert len(self.lookup["patterns"]) >= 5

    def test_required_techniques_present(self) -> None:
        ids = {p["technique_id"] for p in self.lookup["patterns"]}
        for tid in ("T1005", "T1052", "T1567", "T1078", "T1030"):
            assert tid in ids, f"{tid} missing from lookup"

    def test_every_pattern_has_fields(self) -> None:
        for p in self.lookup["patterns"]:
            assert p["pattern"] and p["technique_id"].startswith("T")
            assert p["technique"] and p["tactic"] and p["trigger"]

    def test_lookup_loads_as_valid_json(self) -> None:
        json.dumps(self.lookup)  # must not raise
