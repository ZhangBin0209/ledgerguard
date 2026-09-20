"""Commitment layer tests.

The three claims a commitment binds are tested separately: membership (the
root), interval (the count over a span), and continuity (the link to the
predecessor).  Each has its own attack it defends against.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal

import pytest

from ledgerguard import (
    GENESIS_DIGEST,
    BatchBuilder,
    BatchCommitment,
    Interval,
    check_interval,
    verify_chain,
)
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1

SCHEMA = JOURNAL_ENTRY_V1


def ln(seq, voucher="JV-1", no=1, debit="100.00", credit="0.00", desc=None):
    return {
        "line_seq": seq,
        "voucher_no": voucher,
        "line_no": no,
        "period": "2026-03",
        "posting_date": date(2026, 3, 17),
        "account_code": "1001",
        "debit": Decimal(debit),
        "credit": Decimal(credit),
        "currency": "CNY",
        "description": desc,
        "preparer": "chen.wei",
        "document_ref": None,
    }


def build(seqs, batch_id="B1", prev=GENESIS_DIGEST):
    builder = BatchBuilder(JOURNAL_ENTRY_V1, batch_id, prev)
    builder.extend(ln(s) for s in seqs)
    return builder.seal()


# --------------------------------------------------------------------------
# Interval arithmetic
# --------------------------------------------------------------------------


def test_dense_interval():
    i = Interval(first_seq=10, last_seq=13, count=4)
    assert i.span == 4 and i.is_dense and i.gap_count == 0


def test_sparse_interval_is_legitimate():
    """Voided vouchers leave gaps; a sparse batch must still anchor."""
    i = Interval(first_seq=10, last_seq=20, count=6)
    assert not i.is_dense
    assert i.gap_count == 5


def test_count_may_not_exceed_span():
    with pytest.raises(ValueError, match="exceeds the span"):
        Interval(first_seq=10, last_seq=12, count=4)


def test_reversed_interval_is_rejected():
    with pytest.raises(ValueError, match="exceeds last_seq"):
        Interval(first_seq=20, last_seq=10, count=1)


# --------------------------------------------------------------------------
# Building and sealing
# --------------------------------------------------------------------------


def test_seal_produces_a_consistent_commitment():
    batch = build([1041, 1042, 1043])
    c = batch.commitment
    assert c.interval == Interval(1041, 1043, 3)
    assert c.tree_size == 3 == len(batch)
    assert c.root == batch.tree.root
    assert c.is_genesis
    assert len(c.digest()) == 32


def test_out_of_order_records_are_rejected():
    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B1")
    builder.add(ln(1042))
    with pytest.raises(ValueError, match="ascending"):
        builder.add(ln(1041))


def test_duplicate_sequence_is_rejected():
    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B1")
    builder.add(ln(1041))
    with pytest.raises(ValueError, match="duplicate"):
        builder.add(ln(1041))


def test_malformed_record_is_rejected_at_add_time():
    """Validation happens on add, not at seal, so the offending record is named."""
    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B1")
    bad = ln(1041)
    bad["debit"] = 100.0  # a float straight from a careless ORM
    with pytest.raises(TypeError, match="float"):
        builder.add(bad)
    assert len(builder) == 0


def test_empty_batch_cannot_be_sealed():
    with pytest.raises(ValueError, match="empty"):
        BatchBuilder(JOURNAL_ENTRY_V1, "B1").seal()


def test_schema_without_sequence_field_is_rejected():
    from ledgerguard import FieldSpec, FieldType, RecordSchema

    schema = RecordSchema("test.x", 1, (FieldSpec("a", FieldType.STRING),))
    with pytest.raises(ValueError, match="sequence_field"):
        BatchBuilder(schema, "B1")


def test_prove_by_sequence_number():
    batch = build([1041, 1042, 1043])
    proof = batch.prove_sequence(1042)
    assert proof.index == 1
    assert proof.verify(batch.commitment.root)


# --------------------------------------------------------------------------
# The commitment digest
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutation",
    [
        {"batch_id": "B2"},
        {"schema_version": 2},
        {"interval": Interval(1041, 1043, 3), "tree_size": 3},
        {"prev_digest": b"\x11" * 32},
    ],
)
def test_every_committed_claim_affects_the_digest(mutation):
    base = build([1041, 1042, 1044]).commitment
    if "interval" not in mutation:
        mutation = dict(mutation)
    altered = BatchCommitment(
        batch_id=mutation.get("batch_id", base.batch_id),
        schema_id=base.schema_id,
        schema_version=mutation.get("schema_version", base.schema_version),
        interval=mutation.get("interval", base.interval),
        root=base.root,
        tree_size=mutation.get("tree_size", base.tree_size),
        prev_digest=mutation.get("prev_digest", base.prev_digest),
    )
    assert altered.digest() != base.digest()


def test_root_change_changes_the_digest():
    a = build([1041, 1042]).commitment
    b = build([1041, 1043]).commitment
    assert a.root != b.root
    assert a.digest() != b.digest()


def test_timestamp_is_excluded_from_the_digest():
    """Clock skew must not change what was committed."""
    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B1")
    builder.extend(ln(s) for s in (1, 2, 3))
    early = builder.seal(created_at=datetime(2026, 1, 1, tzinfo=timezone.utc))

    builder2 = BatchBuilder(JOURNAL_ENTRY_V1, "B1")
    builder2.extend(ln(s) for s in (1, 2, 3))
    late = builder2.seal(created_at=datetime(2026, 6, 1, tzinfo=timezone.utc))

    assert early.commitment.digest() == late.commitment.digest()


def test_tree_size_must_match_interval_count():
    with pytest.raises(ValueError, match="disagrees"):
        BatchCommitment(
            batch_id="B1",
            schema_id="x",
            schema_version=1,
            interval=Interval(1, 3, 3),
            root=b"\x00" * 32,
            tree_size=2,
        )


def test_commitment_round_trips_through_dict():
    original = build([1041, 1042, 1045]).commitment
    restored = BatchCommitment.from_dict(original.to_dict())
    assert restored.digest() == original.digest()
    assert restored == original


# --------------------------------------------------------------------------
# Deletion detection via the interval claim
# --------------------------------------------------------------------------


def test_intact_batch_reports_intact():
    batch = build([1041, 1042, 1043, 1044])
    finding = check_interval(batch.commitment, batch.records, JOURNAL_ENTRY_V1)
    assert finding.intact
    assert finding.missing_count == 0


def test_deleted_record_is_detected_by_count():
    """Nothing survives a deleted record; the count shortfall is the evidence."""
    batch = build([1041, 1042, 1043, 1044])
    survivors = [r for r in batch.records if r["line_seq"] != 1043]

    finding = check_interval(batch.commitment, survivors, JOURNAL_ENTRY_V1)
    assert not finding.intact
    assert finding.missing_count == 1
    assert finding.missing_sequences == (1043,)


def test_deleted_record_detected_in_a_sparse_batch():
    """A sparse batch cannot name the missing sequence, but still sees the loss."""
    batch = build([1041, 1043, 1047, 1050])
    assert not batch.commitment.interval.is_dense
    survivors = [r for r in batch.records if r["line_seq"] != 1047]

    finding = check_interval(batch.commitment, survivors, JOURNAL_ENTRY_V1)
    assert not finding.intact
    assert finding.missing_count == 1
    assert finding.missing_sequences == ()  # indistinguishable from a legitimate gap


def test_inserted_record_is_detected():
    """Back-dating a record into an anchored span is equally a violation."""
    batch = build([1041, 1042, 1044])
    tampered = list(batch.records) + [ln(1043)]

    finding = check_interval(batch.commitment, tampered, JOURNAL_ENTRY_V1)
    assert not finding.intact
    assert finding.observed_count == 4 > finding.committed_count


def test_multiple_deletions_are_counted():
    batch = build([1041, 1042, 1043, 1044, 1045])
    survivors = [r for r in batch.records if r["line_seq"] in (1041, 1045)]
    finding = check_interval(batch.commitment, survivors, JOURNAL_ENTRY_V1)
    assert finding.missing_count == 3
    assert finding.missing_sequences == (1042, 1043, 1044)


# --------------------------------------------------------------------------
# Continuity: the defence against deleting a whole batch
# --------------------------------------------------------------------------


def chain_of(n: int) -> list[BatchCommitment]:
    commitments = []
    prev = GENESIS_DIGEST
    for i in range(n):
        batch = build([1000 + i * 10 + j for j in range(3)], f"B{i}", prev)
        commitments.append(batch.commitment)
        prev = batch.commitment.digest()
    return commitments


def test_unbroken_chain_verifies():
    verify_chain(chain_of(5))


def test_removing_a_batch_breaks_the_chain():
    """Each surviving batch is still internally valid; the link is what fails."""
    commitments = chain_of(5)
    truncated = commitments[:2] + commitments[3:]
    with pytest.raises(ValueError, match="chain broken"):
        verify_chain(truncated)


def test_reordering_batches_breaks_the_chain():
    commitments = chain_of(4)
    swapped = [commitments[0], commitments[2], commitments[1], commitments[3]]
    with pytest.raises(ValueError, match="chain broken"):
        verify_chain(swapped)


def test_chain_must_start_at_genesis():
    with pytest.raises(ValueError, match="not a genesis"):
        verify_chain(chain_of(3)[1:])


def test_empty_chain_verifies_vacuously():
    verify_chain([])


@pytest.mark.parametrize("first,last,count", [
    (2**64, 2**64, 1),
    (0, 2**64 - 1, 2**64),
    (-1, 5, 1),
])
def test_out_of_range_interval_bounds_fail_at_construction(first, last, count):
    """Regression: bounds were only checked when the digest was encoded.

    A batch would build and seal successfully and then blow up much later at
    digest time, far from the record that caused it.
    """
    with pytest.raises(ValueError):
        Interval(first_seq=first, last_seq=last, count=count)


def test_the_largest_encodable_interval_still_works():
    interval = Interval(first_seq=2**64 - 2, last_seq=2**64 - 1, count=2)
    commitment = BatchCommitment(
        batch_id="B", schema_id="x", schema_version=1, interval=interval,
        root=b"\x01" * 32, tree_size=2,
    )
    assert len(commitment.digest()) == 32


# --------------------------------------------------------------------------
# The predecessor must be *committed*, not merely recorded
#
# Found by mutation testing: removing prev_digest from the preimage left all
# 331 tests passing. verify_chain compares the prev_digest *field* against the
# predecessor's digest, so it keeps working either way, and the frozen
# commitment vector uses a genesis batch, where the two encodings coincide.
# --------------------------------------------------------------------------


def test_predecessor_changes_the_commitment_digest():
    """Two batches with identical content but different predecessors must not
    share a digest."""
    from ledgerguard import GENESIS_DIGEST

    records = [ln(s) for s in (1, 2, 3)]
    first = BatchBuilder(JOURNAL_ENTRY_V1, "B1", GENESIS_DIGEST)
    first.extend(records)
    second = BatchBuilder(JOURNAL_ENTRY_V1, "B1", b"\xaa" * 32)
    second.extend(records)

    a, b = first.seal().commitment, second.seal().commitment
    assert a.root == b.root          # same content
    assert a.digest() != b.digest()  # different position in the chain


def test_relinking_a_batch_breaks_its_anchored_digest():
    """The attack the committed predecessor prevents.

    An adversary who could re-point a batch at a different predecessor without
    changing its digest could splice a batch out of the chain while every
    anchor still validated. Because the predecessor is part of the preimage,
    the re-linked body no longer hashes to what was anchored.
    """
    from dataclasses import replace

    from ledgerguard import MemoryBackend

    backend = MemoryBackend()
    commitments = []
    for i in range(3):
        builder = BatchBuilder(
            JOURNAL_ENTRY_V1, f"B{i}", backend.next_prev_digest())
        builder.extend(ln(s) for s in (i * 10 + 1, i * 10 + 2))
        sealed = builder.seal()
        backend.anchor(sealed.commitment)
        commitments.append(sealed.commitment)

    relinked = replace(commitments[2], prev_digest=commitments[0].digest())
    assert relinked.digest() != commitments[2].digest()

    # The anchored digest is unchanged, so the re-linked body is refused.
    anchored = backend.fetch("B2")
    assert anchored is not None
    assert relinked.digest() != anchored.digest


def test_genesis_and_explicit_zero_predecessor_agree():
    """GENESIS_DIGEST is a value, not a special case in the encoding."""
    from ledgerguard import GENESIS_DIGEST

    a = BatchBuilder(JOURNAL_ENTRY_V1, "B", GENESIS_DIGEST)
    a.extend([ln(1)])
    b = BatchBuilder(JOURNAL_ENTRY_V1, "B", b"\x00" * 32)
    b.extend([ln(1)])
    assert a.seal().commitment.digest() == b.seal().commitment.digest()


# -- 0.6.8: check_interval is linear in batch size --------------------------


def test_check_interval_is_linear_in_batch_size():
    """Regression: a list-membership scan made this quadratic, 0.3 s per
    10,000-record batch, so verification throughput fell with the batch
    sizes the cost guidance recommends. Same pattern as the 0.6.3 routing
    test: a generous wall-clock bound that a quadratic implementation
    overshoots by an order of magnitude (about 8 s at this size)."""
    import time

    n = 50_000
    records = [{"line_seq": s} for s in range(1, n + 1)]
    commitment = BatchCommitment(
        batch_id="big", schema_id=SCHEMA.schema_id, schema_version=1,
        interval=Interval(1, n, n), root=b"\x11" * 32, tree_size=n,
    )
    start = time.perf_counter()
    finding = check_interval(commitment, records, SCHEMA)
    elapsed = time.perf_counter() - start

    assert finding.intact
    assert elapsed < 1.0, f"check_interval took {elapsed:.2f}s for {n} records"
