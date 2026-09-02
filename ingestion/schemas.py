from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class Event(BaseModel):
    event_id: str
    timestamp: datetime
    user_id: str
    action: str
    target: Optional[str] = None
    host: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    details: Optional[str] = None
    raw: Optional[dict] = None

class LogRecord(BaseModel):
    timestamp: str
    user: str
    pc: Optional[str] = None
    activity: str
    extra: Optional[dict] = None
