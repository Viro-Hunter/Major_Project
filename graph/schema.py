"""Week 3 — graph/schema.py

Pydantic models for the CyberGraphRAG knowledge-graph schema:

  - Entity types   : User, Host, Device, FileResource, EmailEvent,
                     NetworkConnection, AttackTechnique
  - Relation types : LOGGED_IN_FROM, ACCESSED, CONNECTED_DEVICE,
                     SENT_EMAIL_TO, MATCHES_TECHNIQUE

Every entity and relation carries a globally unique id, a type tag, a free-form
attributes dict, a confidence score in [0, 1], and a timestamp. The schema is
the contract that the extraction pipeline (Week 4) must conform to and the
graph store (Week 5) consumes.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------


class EntityType(str, Enum):
    USER = "User"
    HOST = "Host"
    DEVICE = "Device"
    FILE_RESOURCE = "FileResource"
    EMAIL_EVENT = "EmailEvent"
    NETWORK_CONNECTION = "NetworkConnection"
    ATTACK_TECHNIQUE = "AttackTechnique"


class BaseEntity(BaseModel):
    """Common fields for every node in the knowledge graph."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: EntityType
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    timestamp: Optional[str] = None  # ISO-8601 (nullable for static entities)

    model_config = {"use_enum_values": True}


class User(BaseEntity):
    type: EntityType = EntityType.USER  # type: ignore[assignment]


class Host(BaseEntity):
    type: EntityType = EntityType.HOST  # type: ignore[assignment]


class Device(BaseEntity):
    type: EntityType = EntityType.DEVICE  # type: ignore[assignment]


class FileResource(BaseEntity):
    type: EntityType = EntityType.FILE_RESOURCE  # type: ignore[assignment]


class EmailEvent(BaseEntity):
    type: EntityType = EntityType.EMAIL_EVENT  # type: ignore[assignment]


class NetworkConnection(BaseEntity):
    type: EntityType = EntityType.NETWORK_CONNECTION  # type: ignore[assignment]


class AttackTechnique(BaseEntity):
    type: EntityType = EntityType.ATTACK_TECHNIQUE  # type: ignore[assignment]


ENTITY_CLASSES = {
    EntityType.USER: User,
    EntityType.HOST: Host,
    EntityType.DEVICE: Device,
    EntityType.FILE_RESOURCE: FileResource,
    EntityType.EMAIL_EVENT: EmailEvent,
    EntityType.NETWORK_CONNECTION: NetworkConnection,
    EntityType.ATTACK_TECHNIQUE: AttackTechnique,
}


# ---------------------------------------------------------------------------
# Relation types
# ---------------------------------------------------------------------------


class RelationType(str, Enum):
    LOGGED_IN_FROM = "LOGGED_IN_FROM"
    ACCESSED = "ACCESSED"
    CONNECTED_DEVICE = "CONNECTED_DEVICE"
    SENT_EMAIL_TO = "SENT_EMAIL_TO"
    MATCHES_TECHNIQUE = "MATCHES_TECHNIQUE"


class Relation(BaseModel):
    """A typed, scored, timestamped edge between two graph entities."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str
    target_id: str
    type: RelationType
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    timestamp: Optional[str] = None

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Extraction output contract
# ---------------------------------------------------------------------------


class ExtractionTuple(BaseModel):
    """One (entity, entity, relation, confidence) tuple returned by extraction.

    This is the shape extraction/entity_extractor.py produces and the graph
    store consumes.
    """

    source: BaseEntity
    target: BaseEntity
    relation_type: RelationType
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)


def parse_event_timestamp(raw_date: str) -> str:
    """Convert a CERT `date` field (MM/DD/YYYY HH:MM:SS) to ISO-8601.

    Falls back to the raw string if parsing fails, so malformed rows never
    raise during ingestion.
    """
    try:
        dt = datetime.strptime(raw_date.strip(), "%m/%d/%Y %H:%M:%S")
        return dt.isoformat()
    except (ValueError, AttributeError):
        return raw_date
