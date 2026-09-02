from typing import List
from ingestion.schemas import Event
from extraction.entity_extractor import extract_from_event
from .graph_store import GraphStore

def incremental_insert(store: GraphStore, events: List[Event]):
    for ev in events:
        entities, relations = extract_from_event(ev)
        for e in entities:
            store.add_node(e.id, type=e.type.value, risk_baseline=e.risk_baseline, attrs=e.attrs)
        for r in relations:
            store.add_edge(r.source, r.target, relation=r.type.value, base_confidence=r.confidence, evidence=r.evidence)
