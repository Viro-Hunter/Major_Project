import re
from typing import Optional

def extract_entity(query: str, default: Optional[str]=None) -> Optional[str]:
    # look for email, user id, ip, host patterns
    m = re.search(r"[a-zA-Z0-9._-]+@[a-z]+\.[a-z]+", query)
    if m: return m.group(0)
    m = re.search(r"\b\d+\.\d+\.\d+\.\d+\b", query)
    if m: return m.group(0)
    # quoted entity
    m = re.search(r'"([^"]+)"', query)
    if m: return m.group(1)
    # fallback: first token that looks like user (e.g., d.kapoor)
    m = re.search(r"\b[a-z]\.[a-z]+\b", query.lower())
    if m: return m.group(0)
    return default

def parse_query(query: str) -> dict:
    return {"raw": query, "entity_hint": extract_entity(query)}
