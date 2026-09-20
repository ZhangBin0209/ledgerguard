"""The harness's cross-run aggregation, which the paper's noise figures rest on."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from experiments import aggregate_runs


def _row(records, anchor_s, verify_s, spread=0.05):
    return {
        "records": records, "batches": records // 100, "repeats": 5,
        "digest_s": anchor_s / 2, "anchor_s": anchor_s, "verify_s": verify_s,
        "anchor_records_per_s": round(records / anchor_s),
        "verify_records_per_s": round(records / verify_s),
        "anchor_spread": spread, "verify_spread": spread,
    }


def test_single_run_passes_through_with_zero_run_spread():
    run = [_row(1000, 0.02, 0.05), _row(4000, 0.08, 0.20)]
    out = aggregate_runs([run])
    assert [r["records"] for r in out] == [1000, 4000]
    assert out[0]["runs"] == 1
    assert out[0]["anchor_records_per_s"] == 50_000
    assert out[0]["anchor_run_spread"] == 0.0 and out[0]["verify_run_spread"] == 0.0


def test_median_across_runs_and_run_to_run_spread():
    runs = [
        [_row(1000, 0.020, 0.050, spread=0.02)],
        [_row(1000, 0.025, 0.040, spread=0.10)],
        [_row(1000, 0.030, 0.060, spread=0.04)],
    ]
    (row,) = aggregate_runs(runs)
    assert row["runs"] == 3
    assert row["anchor_s"] == 0.025 and row["verify_s"] == 0.05      # medians
    assert row["anchor_spread"] == 0.10                               # worst within-run
    assert row["anchor_run_spread"] == round((0.030 - 0.020) / 0.025, 4)
    assert row["verify_run_spread"] == round((0.060 - 0.040) / 0.050, 4)


def test_sizes_are_matched_across_runs_not_by_position():
    runs = [[_row(1000, 0.02, 0.05), _row(4000, 0.08, 0.2)],
            [_row(4000, 0.09, 0.2), _row(1000, 0.02, 0.06)]]
    out = aggregate_runs(runs)
    assert [(r["records"], r["runs"]) for r in out] == [(1000, 2), (4000, 2)]
