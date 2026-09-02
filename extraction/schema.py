from enum import Enum
from typing import Optional
from pydantic import BaseModel

class EntityType(str, Enum):
    User = "User"
    Host = "Host"
    IP = "IP"
    File = "File"
    Process = "Process"
    Network = "Network"
    ThreatActor = "ThreatActor"
    Resource = "Resource"

class RelationType(str, Enum):
    AuthenticatedTo = "AuthenticatedTo"
    Accessed = "Accessed"
    Copied = "Copied"
    Exfiltration = "Exfiltration"
    PrivEsc = "PrivEsc"
    ConnectedTo = "ConnectedTo"
    SentEmail = "SentEmail"
    LoggedIn = "LoggedIn"
    FailedLogin = "FailedLogin"
    UsedHost = "UsedHost"

class Entity(BaseModel):
    id: str
    type: EntityType
    risk_baseline: float = 0.0
    attrs: Optional[dict] = None

class Relation(BaseModel):
    source: str
    target: str
    type: RelationType
    confidence: float = 0.8
    evidence: Optional[str] = None
