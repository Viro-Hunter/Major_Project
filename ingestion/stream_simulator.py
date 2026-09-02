import time
from typing import List, Iterator
from .schemas import Event

def replay_stream(events: List[Event], speed: float = 10, delay: bool = False) -> Iterator[Event]:
    """Yield events sorted by timestamp. If delay True sleep scaled."""
    events_sorted = sorted(events, key=lambda e: e.timestamp)
    start = None
    for ev in events_sorted:
        if delay and start is not None:
            # minimal sleep scaled
            time.sleep(0.01 / max(speed, 1))
        yield ev
        start = ev.timestamp

def batch(events: List[Event], size: int = 100):
    for i in range(0, len(events), size):
        yield events[i:i+size]
