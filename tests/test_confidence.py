"""Week 9 — multiplicative confidence propagation with daily decay.

Expected values are computed by hand from  PRODUCT(c_i * 0.95 ** age_days_i):

  Path A  0.9 (day 10) -> 0.8 (day 10), as_of day 10   = 0.9 * 0.8                         = 0.72
  Path B  0.9 (day 0)  -> 0.8 (day 2),  as_of day 2    = 0.9 * 0.95**2 * 0.8 = 0.9*0.9025*0.8 = 0.6498
  Path C  1.0 (day 0)  -> 0.5 (day 5) -> 0.8 (day 10), as_of day 10
                       = 1.0*0.95**10 * 0.5*0.95**5 * 0.8 = 0.598737 * 0.386890 * 0.8        ≈ 0.185316
"""
from datetime import datetime

import pytest

from graph.confidence import (
    apply_decay,
    decayed_edge_confidence,
    latest_timestamp,
    multiply_path_confidence,
    noisy_or,
    parse_timestamp,
    path_confidence,
    to_percent,
)

D0 = "2010-01-01T09:00:00"
D2 = "2010-01-03T09:00:00"
D5 = "2010-01-06T09:00:00"
D10 = "2010-01-11T09:00:00"


def test_path_a_same_day_no_decay():
    edges = [{"confidence": 0.9, "timestamp": D10}, {"confidence": 0.8, "timestamp": D10}]
    assert path_confidence(edges) == pytest.approx(0.72)


def test_path_b_two_day_old_edge_decays():
    edges = [{"confidence": 0.9, "timestamp": D0}, {"confidence": 0.8, "timestamp": D2}]
    # as_of defaults to the newest timestamp on the path (D2)
    assert path_confidence(edges) == pytest.approx(0.6498)


def test_path_c_three_hops_mixed_ages():
    edges = [
        {"confidence": 1.0, "timestamp": D0},
        {"confidence": 0.5, "timestamp": D5},
        {"confidence": 0.8, "timestamp": D10},
    ]
    assert path_confidence(edges) == pytest.approx(0.185316, abs=1e-6)


def test_explicit_as_of_overrides_default_and_fractional_days():
    as_of = datetime(2010, 1, 2, 21, 0, 0)  # 1.5 days after D0
    assert path_confidence([{"confidence": 0.9, "timestamp": D0}], as_of=as_of) == pytest.approx(0.9 * 0.95 ** 1.5)


def test_future_or_missing_timestamps_are_not_decayed():
    as_of = parse_timestamp(D0)
    assert decayed_edge_confidence({"confidence": 0.7, "timestamp": D10}, as_of) == pytest.approx(0.7)
    assert decayed_edge_confidence({"confidence": 0.7}, as_of) == pytest.approx(0.7)
    assert decayed_edge_confidence({"timestamp": D0}, as_of) == pytest.approx(1.0)  # missing confidence -> 1.0


def test_confidence_is_clamped_and_cert_dates_parse():
    assert decayed_edge_confidence({"confidence": 1.7}) == 1.0
    assert decayed_edge_confidence({"confidence": -0.2}) == 0.0
    assert parse_timestamp("01/02/2010 08:25:18") == datetime(2010, 1, 2, 8, 25, 18)
    assert parse_timestamp("not a date") is None
    assert latest_timestamp([{"timestamp": D0}, {"timestamp": D5}, {}]) == parse_timestamp(D5)


def test_noisy_or_and_percent():
    assert noisy_or([0.5, 0.4]) == pytest.approx(0.7)
    assert noisy_or([]) == 0.0
    assert to_percent(0.81234) == 81.2


def test_legacy_helpers_unchanged():
    assert apply_decay(0.8, 72) == pytest.approx(0.4)
    assert multiply_path_confidence([0.9, 0.5]) == pytest.approx(0.45)
