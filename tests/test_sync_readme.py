"""The README's measured-behaviour section is generated from results/ so it
cannot drift; these tests pin what the generator reads and how it rewrites."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sync_readme import BEGIN, DASH, END, apply, render


@pytest.fixture
def results(tmp_path):
    (tmp_path / "environment.json").write_text(json.dumps({
        "ledgerguard_version": "9.9.9", "python": "3.12.3",
        "platform": "Linux-6.1-x86_64", "cpu_model": "TestCPU", "cpu_count": 2}))
    (tmp_path / "throughput.csv").write_text(
        "records,batches,repeats,runs,digest_s,anchor_s,verify_s,anchor_records_per_s,"
        "verify_records_per_s,anchor_spread,verify_spread,anchor_run_spread,verify_run_spread\n"
        "246,3,5,3,0.004,0.005,0.013,44000,18000,0.10,0.21,0.17,0.08\n"
        "97930,980,5,3,1.8,2.2,5.6,45600,17510,0.12,0.14,0.02,0.10\n")
    (tmp_path / "gas.csv").write_text(
        "batch_size,gas_used,gas_per_record,first_anchor_gas\n"
        "10,119608,11960.8,136708\n5000,119596,23.9,136708\n")
    (tmp_path / "proof_size.csv").write_text(
        "batch_size,proof_hashes,proof_bytes,verify_us\n16,4,128,2.7\n16384,14,448,10.864\n")
    (tmp_path / "detection.csv").write_text(
        "rate,seed,records,injected,amount_injected,amount_detected,amount_recall,"
        "deletion_injected,deletion_detected,deletion_recall,period_injected,"
        "period_detected,period_recall,sequence_injected,sequence_detected,"
        "sequence_recall,false_positives\n"
        "0.01,0,4818,48,12,12,1.0,12,12,1.0,12,12,1.0,12,12,1.0,0\n"
        "0.05,1,4854,243,61,61,1.0,61,61,1.0,61,61,1.0,60,60,1.0,0\n")
    return tmp_path


def test_every_quoted_number_comes_from_results(results):
    text = render(results)
    assert "v9.9.9" in text and "TestCPU" in text and "2-core" in text
    assert f"44,000{DASH}45,600 records/s" in text and f"17,500{DASH}18,000 records/s" in text
    assert "within-run spread ≤ 12%, run-to-run ≤ 17%" in text     # anchor
    assert "within-run spread ≤ 21%, run-to-run ≤ 10%" in text     # verify
    assert "within-run spread reaches 21% and run-to-run spread 17%" in text
    assert f"119,596{DASH}119,608 across batches of 10{DASH}5,000" in text
    assert "14 hashes (448 B) at 16,384 records; verify in ~11 µs" in text
    assert "291 injected manipulations over 2 seeded runs: 100% recall" in text
    assert "0 false positives" in text


def test_apply_replaces_only_the_marked_section(results):
    readme = f"# Title\n\nintro\n\n{BEGIN}\nold stuff\n{END}\n\nkept tail\n"
    out = apply(readme, render(results))
    assert out.startswith("# Title\n\nintro\n\n" + BEGIN)
    assert out.endswith(END + "\n\nkept tail\n")
    assert "old stuff" not in out and "v9.9.9" in out


def test_single_run_results_render_without_run_to_run_figures(results):
    (results / "throughput.csv").write_text(
        "records,batches,repeats,digest_s,anchor_s,verify_s,anchor_records_per_s,"
        "verify_records_per_s,anchor_spread,verify_spread\n"
        "246,3,5,0.004,0.005,0.013,44000,18000,0.10,0.21\n")
    text = render(results)
    assert "run-to-run" not in text and "medians of 5 repeats" in text
