import math
from typing import List

DECAY_HALF_LIFE_HOURS = 72  # confidence halves every 72h

def apply_decay(edge_conf: float, hours_old: float, half_life: float = DECAY_HALF_LIFE_HOURS) -> float:
    if hours_old <= 0:
        return edge_conf
    return edge_conf * (0.5 ** (hours_old / half_life))

def multiply_path_confidence(confidences: List[float]) -> float:
    p = 1.0
    for c in confidences:
        p *= max(0.0, min(1.0, c))
    return p

def compute_edge_confidence(base: float, trust: float = 1.0, hours_old: float = 0) -> float:
    decayed = apply_decay(base * trust, hours_old)
    return max(0.0, min(1.0, decayed))
