"""Verifier tests.

The verifier is tested at all three levels of evidence: with a witness (which
names records), without one (root and interval only), and with a doctored
witness (which must be rejected before it is used to accuse anyone).
"""

from __future__ import annotations

import pytest

from ledgerguard import (
    BatchBuilder,
    BatchStatus,
    BatchWitness,
    MemoryBackend,
    Verdict,
    Verifier,
    format_report,
    synth,
    tamper,
)
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1
from ledgerguard.tamper import AttackClass

SCHEMA = JOURNAL_ENTRY_V1


@pytest.fixture
def anchored():
    """A three-batch anchored ledger with witnesses retained."""
    ledger = synth.generate(vouchers=30, seed=7, batch_size=20)
    backend = MemoryBackend()
    witnesses = {}
    for i, chunk in enumerate(ledger.batches()):
        builder = BatchBuilder(SCHEMA, f"B{i}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()
    return ledger, backend, witnesses


# -- clean ledger -----------------------------------------------------------

def test_untouched_ledger_verifies(anchored):
    ledger, backend, witnesses = anchored
    report = Verifier(backend, SCHEMA).verify_ledger(ledger.records, witnesses)
    assert report.intact
    assert report.chain_intact
    assert report.count(Verdict.MODIFIED) == 0
    assert "no discrepancies" in report.summary()


def test_untouched_ledger_verifies_without_witnesses(anchored):
    ledger, backend, _ = anchored
    report = Verifier(backend, SCHEMA).verify_ledger(ledger.records)
    assert report.intact


# -- each attack class ------------------------------------------------------

def test_amount_alteration_is_attributed(anchored):
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=3, amount=2)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    assert not report.intact
    assert report.count(Verdict.MODIFIED) == 2
    flagged = {f.sequence for b in report.batches for f in b.by_verdict(Verdict.MODIFIED)}
    assert flagged == set(result.log.sequences_of(AttackClass.AMOUNT))


def test_deletion_is_attributed(anchored):
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=4, deletion=3)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    assert report.count(Verdict.DELETED) == 3
    flagged = {f.sequence for b in report.batches for f in b.by_verdict(Verdict.DELETED)}
    assert flagged == set(result.log.sequences_of(AttackClass.DELETION))


def test_period_shift_is_attributed(anchored):
    """A cut-off manipulation still balances; only the digest reveals it."""
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=5, period=2)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    assert report.count(Verdict.MODIFIED) == 2
    flagged = {f.sequence for b in report.batches for f in b.by_verdict(Verdict.MODIFIED)}
    assert flagged == set(result.log.sequences_of(AttackClass.PERIOD))


def test_insertion_is_attributed(anchored):
    """A duplicate row at an anchored sequence must not displace the genuine one."""
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=6, sequence=2)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    assert not report.intact
    assert report.count(Verdict.INSERTED) == 2
    assert report.count(Verdict.MODIFIED) == 0  # the original is still intact
    flagged = {f.sequence for b in report.batches for f in b.by_verdict(Verdict.INSERTED)}
    assert flagged == set(result.log.sequences_of(AttackClass.SEQUENCE))


def test_all_classes_together(anchored):
    ledger, backend, witnesses = anchored
    result = tamper.inject(
        ledger.records, seed=8, amount=2, deletion=2, period=2, sequence=1)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    assert not report.intact
    assert report.count(Verdict.MODIFIED) == 4   # amount + period
    assert report.count(Verdict.DELETED) == 2
    assert report.count(Verdict.INSERTED) == 1
    assert len(report.tampered_batches) >= 1


# -- degraded evidence ------------------------------------------------------

def test_without_witness_detects_but_cannot_attribute(anchored):
    """Root mismatch proves tampering; naming the record needs the witness."""
    ledger, backend, _ = anchored
    result = tamper.inject(ledger.records, seed=9, amount=1)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records)

    assert not report.intact
    assert report.count(Verdict.MODIFIED) == 0  # no attribution
    assert any("no witness" in b.detail for b in report.tampered_batches)


def test_without_witness_interval_still_catches_deletion(anchored):
    """The weakest check survives the loss of all per-record evidence."""
    ledger, backend, _ = anchored
    result = tamper.inject(ledger.records, seed=10, deletion=2)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records)

    assert not report.intact
    shortfall = sum(b.interval.missing_count for b in report.batches if b.interval)
    assert shortfall == 2


def test_doctored_witness_is_rejected(anchored):
    """A witness that does not rebuild the anchored root cannot accuse anyone."""
    ledger, backend, witnesses = anchored
    good = witnesses["B0"]
    forged = BatchWitness(
        batch_id=good.batch_id,
        sequences=good.sequences,
        digests=(b"\x99" * 32,) + good.digests[1:],
    )
    report = Verifier(backend, SCHEMA).verify_batch(
        "B0", ledger.batches()[0], forged)

    assert report.status is BatchStatus.WITNESS_INVALID
    assert report.findings == ()


def test_unanchored_batch_is_reported(anchored):
    _, backend, _ = anchored
    report = Verifier(backend, SCHEMA).verify_batch("nonexistent", [])
    assert report.status is BatchStatus.NOT_ANCHORED


# -- chain-level --------------------------------------------------------

def test_whole_batch_removal_breaks_the_chain(anchored):
    """Each surviving batch verifies; the chain link is what fails."""
    from ledgerguard import verify_chain
    _, backend, _ = anchored
    partial = [c for c in backend.chain() if c.batch_id != "B1"]
    with pytest.raises(ValueError, match="chain broken"):
        verify_chain(partial)


# -- report rendering -------------------------------------------------------

def test_report_serialises_to_dict(anchored):
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=11, amount=1, deletion=1)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    data = report.to_dict()
    assert data["intact"] is False
    assert data["totals"]["modified"] == 1
    assert data["totals"]["deleted"] == 1
    assert all("batch_id" in b for b in data["batches"])


def test_format_report_names_the_findings(anchored):
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=12, amount=1)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    text = format_report(report)
    assert "FAIL" in text
    seq = next(iter(result.log.sequences_of(AttackClass.AMOUNT)))
    assert f"seq {seq}" in text


def test_findings_carry_inclusion_proofs(anchored):
    ledger, backend, witnesses = anchored
    result = tamper.inject(ledger.records, seed=13, amount=1)
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    batch = next(b for b in report.batches if b.by_verdict(Verdict.MODIFIED))
    finding = batch.by_verdict(Verdict.MODIFIED)[0]

    assert finding.anchored_digest != finding.observed_digest
    # The proof is over the anchored digest, so it still reconstructs the
    # anchored root -- that is what makes it usable as evidence that the
    # anchored record was a different record.
    assert finding.proof is not None
    assert finding.proof.verify(batch.anchored_root)


def test_schema_mismatch_is_named_not_reported_as_mass_tampering(anchored):
    """Verifying against another profile's anchors must say so in one line.

    Without this check every record is reported as modified -- technically
    true, and useless. The commitment records its schema for exactly this.
    """
    from ledgerguard.profiles import get_profile

    ledger, backend, witnesses = anchored
    wrong = Verifier(backend, get_profile("provenance"))
    report = wrong.verify_batch("B0", [], witnesses.get("B0"))

    assert report.status is BatchStatus.SCHEMA_MISMATCH
    assert "accounting.journal_entry" in report.detail
    assert "provenance.instrument_event" in report.detail
    assert report.findings == ()


def test_schema_mismatch_dominates_the_ledger_summary(anchored):
    from ledgerguard.profiles import get_profile

    ledger, backend, witnesses = anchored
    report = Verifier(backend, get_profile("provenance")).verify_ledger([], {})

    assert not report.intact
    assert "different schema" in report.summary()
    assert "--profile" in report.summary()


def test_record_inserted_between_anchored_batches_is_reported(anchored):
    """Regression: span-based routing dropped records that fell in no span.

    Batches cover 1..n and m..k with a gap between them. A record inserted
    into that gap belongs to no batch, and routing by span silently discarded
    it -- an intruder who wrote between two batch boundaries was invisible.
    """
    ledger, backend, witnesses = anchored
    spans = [c.interval for c in backend.chain()]
    assert len(spans) >= 2

    orphan_seq = max(s.last_seq for s in spans) + 1000
    intruder = dict(ledger.records[0])
    intruder["line_seq"] = orphan_seq

    report = Verifier(backend, SCHEMA).verify_ledger(
        list(ledger.records) + [intruder], witnesses)

    assert not report.intact
    assert report.orphan_sequences == (orphan_seq,)
    assert "outside every anchored range" in report.summary()
    assert str(orphan_seq) in format_report(report)


def test_orphans_appear_in_the_json_report(anchored):
    ledger, backend, witnesses = anchored
    intruder = dict(ledger.records[0])
    intruder["line_seq"] = 10_000_000

    report = Verifier(backend, SCHEMA).verify_ledger(
        list(ledger.records) + [intruder], witnesses)
    assert report.to_dict()["orphan_sequences"] == [10_000_000]


def test_a_clean_ledger_has_no_orphans(anchored):
    ledger, backend, witnesses = anchored
    report = Verifier(backend, SCHEMA).verify_ledger(ledger.records, witnesses)
    assert report.orphan_sequences == ()


# --------------------------------------------------------------------------
# Complexity
#
# verify_ledger must not be O(batches x records). Two independent quadratic
# terms were found by measuring at realistic scale rather than by reading
# the code: routing records to batches scanned every record for every
# batch, and verify_ledger re-fetched each commitment it already held (see
# test_backends.py for the FileBackend half of that one). At 980 batches
# over 98,000 records this cost 20.4s; fixed, it costs about 5s -- and
# critically, throughput stops degrading with scale instead of falling by
# 4x, since the software's own cost advice depends on that being false.
# --------------------------------------------------------------------------


def _count_backend_reads(backend, fn):
    """Number of times `backend.chain()` or `backend.fetch()` run during `fn`."""
    calls = 0
    original_chain, original_fetch = backend.chain, backend.fetch

    def counting_chain():
        nonlocal calls
        calls += 1
        return original_chain()

    def counting_fetch(batch_id):
        nonlocal calls
        calls += 1
        return original_fetch(batch_id)

    backend.chain, backend.fetch = counting_chain, counting_fetch
    try:
        fn()
    finally:
        backend.chain, backend.fetch = original_chain, original_fetch
    return calls


def test_verify_ledger_reads_the_backend_a_constant_number_of_times(anchored):
    """One call to `chain()` for the whole ledger, and no `fetch()` at all.

    Re-deriving a commitment via `fetch(batch_id)` when `verify_ledger`
    already holds it from `chain()` is a second, redundant lookup -- and on
    `FileBackend` specifically, one that re-reads the whole anchor file. That
    turned an N-batch ledger into an O(N^2) file scan.
    """
    ledger, backend, witnesses = anchored
    reads = _count_backend_reads(
        backend, lambda: Verifier(backend, SCHEMA).verify_ledger(
            ledger.records, witnesses))
    assert reads == 1


def test_routing_records_to_batches_is_subquadratic():
    """Routing must not scan every record for every batch.

    Records are already sorted by sequence, so each batch's slice is found by
    binary search; scanning is what turned routing into O(batches x records).
    """
    import time

    ledger = synth.generate(vouchers=1200, seed=11, batch_size=2)
    backend = MemoryBackend()
    witnesses = {}
    for i, chunk in enumerate(ledger.batches()):
        builder = BatchBuilder(SCHEMA, f"B{i}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()
    n_batches = len(witnesses)

    start = time.perf_counter()
    report = Verifier(backend, SCHEMA).verify_ledger(ledger.records, witnesses)
    elapsed = time.perf_counter() - start

    assert report.intact
    # A quadratic implementation costs on the order of batches^2 comparisons;
    # this generously allows for one that is merely superlinear while still
    # catching a return to O(n^2), which took several seconds at this size.
    assert elapsed < 2.0, f"routing {n_batches} batches took {elapsed:.2f}s"


# -- 0.6.8 ------------------------------------------------------------------


def test_a_ledger_with_no_anchors_at_all_is_not_intact():
    """Regression: with nothing to compare against, the verifier answered
    "no discrepancies". Now every record is outside every anchored span."""
    from ledgerguard import MemoryBackend, synth

    ledger = synth.generate(vouchers=10, seed=5)
    report = Verifier(MemoryBackend(), SCHEMA).verify_ledger(ledger.records, {})

    assert not report.intact
    assert report.orphan_sequences == ledger.sequences
    assert "outside every anchored range" in report.summary()


def test_nothing_observed_and_nothing_anchored_is_vacuously_intact():
    from ledgerguard import MemoryBackend

    report = Verifier(MemoryBackend(), SCHEMA).verify_ledger([], {})
    assert report.intact  # the CLI refuses this case before it gets here


def test_summary_reports_a_count_shortfall_when_no_witness_is_held(anchored):
    """Regression: the first line said "root mismatch without record-level
    attribution" while the batch detail said "5 records missing"."""
    ledger, backend, _ = anchored
    seqs = ledger.sequences[2:7]
    observed = [r for r in ledger.records if r["line_seq"] not in seqs]

    report = Verifier(backend, SCHEMA).verify_ledger(observed, {})

    assert not report.intact
    assert "5 missing against committed counts" in report.summary()
    assert "root mismatch without" not in report.summary()


def test_summary_reports_a_count_surplus_when_no_witness_is_held(anchored):
    ledger, backend, _ = anchored
    extra = dict(ledger.records[3])
    extra["voucher_no"] = "JV-DUP"
    report = Verifier(backend, SCHEMA).verify_ledger(
        [*ledger.records, extra], {})
    assert "1 present beyond committed counts" in report.summary()


def test_summary_names_a_root_mismatch_without_witness(anchored):
    ledger, backend, _ = anchored
    observed = [dict(r) for r in ledger.records]
    observed[0]["debit"] = observed[0]["debit"] + 1  # content only; count intact
    report = Verifier(backend, SCHEMA).verify_ledger(observed, {})
    assert "1 batch with a root mismatch and no witness" in report.summary()


def test_summary_names_a_rejected_witness(anchored):
    from ledgerguard import BatchWitness

    ledger, backend, witnesses = anchored
    batch_id, witness = next(iter(witnesses.items()))
    doctored = BatchWitness(batch_id, witness.sequences,
                            tuple(reversed(witness.digests)))
    report = Verifier(backend, SCHEMA).verify_ledger(
        ledger.records, {**witnesses, batch_id: doctored})
    assert "1 witness rejected" in report.summary()
