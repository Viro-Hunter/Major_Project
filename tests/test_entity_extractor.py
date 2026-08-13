"""Week 4 — tests/test_entity_extractor.py

Mocks the LLM call (no real API keys / network needed). Covers:
- correct parsing of well-formed JSON into schema entities/relations
- retry-once when the first response is malformed JSON
- ExtractionError when both attempts fail
- empty event window returns nothing
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

from extraction.entity_extractor import (  # noqa: E402
    ExtractionError,
    extract,
)
from graph.schema import EntityType, RelationType  # noqa: E402
from ingestion.log_parser import Event, LogType  # noqa: E402


def make_event(**overrides) -> Event:
    kw = dict(
        user="CTR0341",
        timestamp="2010-01-02T07:14:00",
        event_type=LogType.LOGON,
        raw_fields={"pc": "PC-6184", "activity": "Logon"},
        event_id="{S9A0-A3DP89HG-6719JORU}",
    )
    kw.update(overrides)
    return Event(**kw)


GOOD_RESPONSE = json.dumps(
    {
        "entities": [
            {"id": "user-1", "type": "User", "attributes": {"username": "CTR0341"}, "confidence": 0.9, "timestamp": "2010-01-02T07:14:00"},
            {"id": "host-1", "type": "Host", "attributes": {"hostname": "PC-6184"}, "confidence": 0.9, "timestamp": "2010-01-02T07:14:00"},
        ],
        "relations": [
            {"source_id": "user-1", "target_id": "host-1", "type": "LOGGED_IN_FROM", "confidence": 0.9, "timestamp": "2010-01-02T07:14:00"},
        ],
    }
)

GOOD_WITH_FENCES = "```json\n" + GOOD_RESPONSE + "\n```"

MALFORMED = "this is not json at all {{{"

UNKNOWN_ENTITY_TYPE_RESPONSE = json.dumps(
    {
        "entities": [{"id": "x", "type": "NonexistentType", "attributes": {}, "confidence": 0.9, "timestamp": None}],
        "relations": [{"source_id": "a", "target_id": "b", "type": "NOT_A_REAL_TYPE", "confidence": 0.9, "timestamp": None}],
    }
)


@pytest.fixture()
def good_client():
    client = MagicMock()
    client.call.return_value = MagicMock(content=GOOD_RESPONSE)
    return client


class TestExtractionGoodJson:
    def test_parses_entities_and_relations(self, good_client) -> None:
        events = [make_event()]
        entities, relations = extract(good_client, events)
        assert len(entities) == 2
        assert entities[0].type == EntityType.USER
        assert entities[1].type == EntityType.HOST
        assert len(relations) == 1
        assert relations[0].type == RelationType.LOGGED_IN_FROM
        assert relations[0].confidence == 0.9

    def test_strips_markdown_fences_on_retry(self) -> None:
        call_count = {"n": 0}

        def side_effect(system, user):
            call_count["n"] += 1
            content = MALFORMED if call_count["n"] == 1 else GOOD_WITH_FENCES
            return MagicMock(content=content)

        client = MagicMock()
        client.call.side_effect = side_effect
        entities, relations = extract(client, [make_event()])
        assert call_count["n"] == 2
        assert len(entities) == 2
        assert len(relations) == 1

    def test_skips_unknown_entity_and_relation_types(self) -> None:
        client = MagicMock()
        client.call.return_value = MagicMock(content=UNKNOWN_ENTITY_TYPE_RESPONSE)
        entities, relations = extract(client, [make_event()])
        assert entities == []
        assert relations == []


class TestExtractionBadJson:
    def test_retries_once_then_raises(self) -> None:
        client = MagicMock()
        client.call.return_value = MagicMock(content=MALFORMED)
        with pytest.raises(ExtractionError):
            extract(client, [make_event()], max_retries=1)
        assert client.call.call_count == 2  # initial + one retry

    def test_no_events_returns_empty(self, good_client) -> None:
        entities, relations = extract(good_client, [])
        assert entities == [] and relations == []
        good_client.call.assert_not_called()


class TestExtractionPrompt:
    def test_prompt_contains_event_window(self, good_client) -> None:
        events = [make_event(), make_event(activity="Connect", event_type=LogType.DEVICE)]
        extract(good_client, events)
        call_kwargs = good_client.call.call_args
        user_prompt = call_kwargs[0][1]
        assert "CTR0341" in user_prompt
        assert "PC-6184" in user_prompt
        assert "Connect" in user_prompt

    def test_prompt_contains_technique_lookup(self, good_client) -> None:
        extract(good_client, [make_event()])
        user_prompt = good_client.call.call_args[0][1]
        assert "T1052" in user_prompt or "lookup unavailable" in user_prompt
