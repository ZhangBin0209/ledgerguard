"""Generator and injector tests.

Two things must hold for these to be usable as research infrastructure:
generation is reproducible from a seed, and every injected manipulation is
recorded in the ground truth exactly once.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from ledgerguard import record_digest, synth, tamper
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1, validate_voucher_balance
from ledgerguard.synth import LedgerSpec
from ledgerguard.tamper import AttackClass

SCHEMA = JOURNAL_ENTRY_V1


# -- generation -------------------------------------------------------------

def test_same_seed_gives_an_identical_ledger():
    a = synth.generate(vouchers=40, seed=42)
    b = synth.generate(vouchers=40, seed=42)
    assert [record_digest(r, SCHEMA) for r in a] == [record_digest(r, SCHEMA) for r in b]


def test_different_seeds_give_different_ledgers():
    a = synth.generate(vouchers=40, seed=1)
    b = synth.generate(vouchers=40, seed=2)
    assert [record_digest(r, SCHEMA) for r in a] != [record_digest(r, SCHEMA) for r in b]


def test_every_voucher_balances():
    ledger = synth.generate(vouchers=200, seed=3)
    validate_voucher_balance(ledger.records)


def test_sequences_are_monotonic_and_dense():
    ledger = synth.generate(vouchers=100, seed=4)
    seqs = ledger.sequences
    assert list(seqs) == sorted(seqs)
    assert seqs == tuple(range(seqs[0], seqs[0] + len(seqs)))


def test_voided_vouchers_leave_gaps_in_voucher_numbers():
    """Voucher numbers are sparse; line sequences are not. This is why the
    schema carries both, and why deletion detection uses the latter."""
    ledger = synth.generate(vouchers=300, seed=5, void_rate=0.2)
    numbers = sorted({int(r["voucher_no"].split("-")[-1]) for r in ledger})
    assert numbers[-1] - numbers[0] + 1 > len(numbers)   # gaps present
    assert len(set(ledger.sequences)) == len(ledger)     # sequences unbroken


def test_every_record_canonicalises():
    ledger = synth.generate(vouchers=100, seed=6)
    assert all(len(record_digest(r, SCHEMA)) == 32 for r in ledger)


def test_batches_partition_the_ledger():
    ledger = synth.generate(vouchers=60, seed=7, batch_size=25)
    batches = ledger.batches()
    assert sum(len(b) for b in batches) == len(ledger)
    assert all(len(b) <= 25 for b in batches)


def test_multi_line_vouchers_are_produced():
    ledger = synth.generate(vouchers=200, seed=8, multi_line_rate=0.5)
    sizes = {len(v) for v in synth.group_by_voucher(ledger.records).values()}
    assert max(sizes) > 2


def test_copy_is_independent():
    ledger = synth.generate(vouchers=10, seed=9)
    duplicate = ledger.copy()
    duplicate.records[0]["debit"] = Decimal("999999.00")
    assert ledger.records[0]["debit"] != Decimal("999999.00")


@pytest.mark.parametrize("bad", [{"vouchers": 0}, {"batch_size": 0}, {"void_rate": 1.5}])
def test_invalid_spec_is_rejected(bad):
    with pytest.raises(ValueError):
        LedgerSpec(**bad)


# -- injection --------------------------------------------------------------

def test_ground_truth_counts_match_the_request():
    ledger = synth.generate(vouchers=100, seed=10)
    result = tamper.inject(ledger.records, seed=1, amount=5, deletion=3, period=2, sequence=1)
    assert result.log.counts() == {"amount": 5, "deletion": 3, "period": 2, "sequence": 1}
    assert len(result.log) == 11


def test_each_record_is_manipulated_at_most_once():
    """Overlapping attacks would make the ground truth unscorable."""
    ledger = synth.generate(vouchers=100, seed=11)
    result = tamper.inject(ledger.records, seed=2, amount=10, deletion=10, period=10, sequence=10)
    touched = [e.sequence for e in result.log]
    assert len(touched) == len(set(touched))


def test_injection_is_reproducible():
    ledger = synth.generate(vouchers=80, seed=12)
    a = tamper.inject(ledger.records, seed=99, amount=4, deletion=2)
    b = tamper.inject(ledger.records, seed=99, amount=4, deletion=2)
    assert a.log.sequences == b.log.sequences


def test_original_ledger_is_not_mutated():
    ledger = synth.generate(vouchers=50, seed=13)
    before = [record_digest(r, SCHEMA) for r in ledger]
    tamper.inject(ledger.records, seed=3, amount=5, deletion=5, period=5)
    assert [record_digest(r, SCHEMA) for r in ledger] == before


def test_deletion_removes_records():
    ledger = synth.generate(vouchers=50, seed=14)
    result = tamper.inject(ledger.records, seed=4, deletion=7)
    assert len(result.records) == len(ledger) - 7
    surviving = {r["line_seq"] for r in result.records}
    assert not (surviving & result.log.sequences_of(AttackClass.DELETION))


def test_amount_alteration_changes_the_digest():
    ledger = synth.generate(vouchers=50, seed=15)
    result = tamper.inject(ledger.records, seed=5, amount=3)
    by_seq = {r["line_seq"]: r for r in ledger}
    after = {r["line_seq"]: r for r in result.records}
    for seq in result.log.sequences_of(AttackClass.AMOUNT):
        assert record_digest(by_seq[seq], SCHEMA) != record_digest(after[seq], SCHEMA)


def test_period_shift_crosses_a_reporting_boundary():
    ledger = synth.generate(vouchers=80, seed=16)
    result = tamper.inject(ledger.records, seed=6, period=5)
    by_seq = {r["line_seq"]: r for r in ledger}
    after = {r["line_seq"]: r for r in result.records}
    shifted = [s for s in result.log.sequences_of(AttackClass.PERIOD)
               if by_seq[s]["period"] != after[s]["period"]]
    assert shifted, "a cut-off manipulation should move at least one period"


def test_insertion_adds_a_duplicate_sequence():
    ledger = synth.generate(vouchers=50, seed=17)
    result = tamper.inject(ledger.records, seed=7, sequence=2)
    assert len(result.records) == len(ledger) + 2
    seqs = [r["line_seq"] for r in result.records]
    assert len(seqs) != len(set(seqs))


def test_tampered_records_stay_sorted():
    ledger = synth.generate(vouchers=60, seed=18)
    result = tamper.inject(ledger.records, seed=8, amount=3, deletion=3, sequence=2)
    seqs = [r["line_seq"] for r in result.records]
    assert seqs == sorted(seqs)


def test_proportional_injection_spreads_across_classes():
    ledger = synth.generate(vouchers=200, seed=19)
    result = tamper.inject_proportional(ledger.records, rate=0.02, seed=9)
    counts = result.log.counts()
    assert all(c > 0 for c in counts.values())
    assert abs(len(result.log) - round(len(ledger) * 0.02)) <= len(AttackClass)


def test_requesting_more_than_available_is_capped():
    ledger = synth.generate(vouchers=3, seed=20)
    result = tamper.inject(ledger.records, seed=10, amount=1000)
    assert len(result.log) <= len(ledger)


def test_log_serialises():
    ledger = synth.generate(vouchers=30, seed=21)
    result = tamper.inject(ledger.records, seed=11, amount=2, deletion=1)
    data = result.log.to_dict()
    assert data["total"] == 3
    assert len(data["events"]) == 3
    assert all("attack" in e for e in data["events"])
