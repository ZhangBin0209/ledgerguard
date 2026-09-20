"""Batch commitments: what actually goes on the chain.

A Merkle root alone is not enough to make a ledger tamper-evident.  It proves
that a record you already hold was included, but it says nothing about what
*else* was in the batch, so a record removed from the source database leaves
no trace to check against -- there is no surviving digest to re-hash.

The commitment therefore binds three claims, not one:

1.  **Membership.**  The Merkle root over the record digests, with the leaf
    count, so a record's content and position can be proven.
2.  **Interval.**  The batch holds exactly ``count`` records whose sequence
    numbers run from ``first_seq`` to ``last_seq``.  Deleting a record from
    the source leaves the span intact but the count short, and that gap is
    visible without any surviving per-record evidence.
3.  **Continuity.**  Each commitment carries the digest of its predecessor,
    forming a hash chain over batches.  Without it an adversary could delete
    an entire batch: every surviving batch would still verify on its own, and
    nothing would record that a batch had ever existed between two others.

Note what the interval claim does *not* require.  Real ledgers have gaps --
voided vouchers, reserved ranges, numbers burned by a failed transaction.
The committed ``count`` is the ground truth, so a batch that was sparse when
anchored stays valid; what a later verification detects is a count that has
*fallen below* what was committed.  Requiring density at anchoring time would
have made the tool unusable against real data on the first day.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import pairwise
from typing import Any, Iterable, Iterator, Mapping, Sequence

from ._encoding import UINT64_MAX, lp, lp_text, u32, u64
from .canonical import record_digest
from .merkle import DIGEST_SIZE, MerkleTree
from .schema import RecordSchema

# Domain separation: a commitment preimage must never be confusable with a
# record preimage or a Merkle node preimage.
_COMMITMENT_TAG = b"\x02lg-commitment-v1"

#: Predecessor digest used by the first commitment in a chain.
GENESIS_DIGEST = b"\x00" * DIGEST_SIZE


@dataclass(frozen=True)
class Interval:
    """The claim that a batch holds ``count`` records over a sequence span."""

    first_seq: int
    last_seq: int
    count: int

    def __post_init__(self) -> None:
        if self.count < 1:
            raise ValueError("an interval must cover at least one record")
        # Bounds are checked here rather than at encoding time. Deferring the
        # check would let a batch build and seal successfully and only fail
        # when its digest is computed, which is far from the record that
        # caused it.
        for name in ("first_seq", "last_seq", "count"):
            value = getattr(self, name)
            if not 0 <= value <= UINT64_MAX:
                raise ValueError(
                    f"{name} of {value} does not fit in the 64-bit field the "
                    "commitment encodes it in"
                )
        if self.first_seq > self.last_seq:
            raise ValueError(
                f"first_seq {self.first_seq} exceeds last_seq {self.last_seq}"
            )
        if self.count > self.span:
            raise ValueError(
                f"count {self.count} exceeds the span of {self.span} available "
                "sequence numbers"
            )

    @property
    def span(self) -> int:
        """Number of sequence positions the interval covers, inclusive."""
        return self.last_seq - self.first_seq + 1

    @property
    def is_dense(self) -> bool:
        """Whether the batch fills its span with no gaps.

        Informational only.  A sparse batch is legitimate; density is not a
        precondition for anchoring.
        """
        return self.count == self.span

    @property
    def gap_count(self) -> int:
        """Sequence positions inside the span that hold no record."""
        return self.span - self.count

    def encode(self) -> bytes:
        return u64(self.first_seq) + u64(self.last_seq) + u64(self.count)


@dataclass(frozen=True)
class BatchCommitment:
    """The full commitment for one batch.

    Only :meth:`digest` is written to the chain.  The body is kept off-chain
    and must re-hash to the anchored digest, which is what keeps on-chain
    storage constant regardless of batch size.
    """

    batch_id: str
    schema_id: str
    schema_version: int
    interval: Interval
    root: bytes
    tree_size: int
    prev_digest: bytes = GENESIS_DIGEST
    created_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.batch_id:
            raise ValueError("batch_id must be non-empty")
        if len(self.root) != DIGEST_SIZE:
            raise ValueError(f"root must be {DIGEST_SIZE} bytes")
        if len(self.prev_digest) != DIGEST_SIZE:
            raise ValueError(f"prev_digest must be {DIGEST_SIZE} bytes")
        if self.tree_size != self.interval.count:
            raise ValueError(
                f"tree_size {self.tree_size} disagrees with interval count "
                f"{self.interval.count}"
            )
        if self.created_at is not None and self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")

    @property
    def is_genesis(self) -> bool:
        return self.prev_digest == GENESIS_DIGEST

    def preimage(self) -> bytes:
        """The exact bytes hashed by :meth:`digest`.

        Exposed so that a disputed commitment can be inspected rather than
        merely re-hashed.  ``created_at`` is deliberately excluded: the
        anchoring transaction already carries an authoritative timestamp, and
        including a locally generated one would make the digest depend on
        clock skew.
        """
        return b"".join(
            [
                _COMMITMENT_TAG,
                lp_text(self.batch_id),
                lp_text(self.schema_id),
                u32(self.schema_version),
                self.interval.encode(),
                lp(self.root),
                u64(self.tree_size),
                lp(self.prev_digest),
            ]
        )

    def digest(self) -> bytes:
        """The 32-byte value written to the chain."""
        return hashlib.sha256(self.preimage()).digest()

    def digest_hex(self) -> str:
        return self.digest().hex()

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly form for off-chain storage."""
        return {
            "batch_id": self.batch_id,
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "first_seq": self.interval.first_seq,
            "last_seq": self.interval.last_seq,
            "count": self.interval.count,
            "root": self.root.hex(),
            "tree_size": self.tree_size,
            "prev_digest": self.prev_digest.hex(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BatchCommitment:
        created = data.get("created_at")
        return cls(
            batch_id=data["batch_id"],
            schema_id=data["schema_id"],
            schema_version=int(data["schema_version"]),
            interval=Interval(
                first_seq=int(data["first_seq"]),
                last_seq=int(data["last_seq"]),
                count=int(data["count"]),
            ),
            root=bytes.fromhex(data["root"]),
            tree_size=int(data["tree_size"]),
            prev_digest=bytes.fromhex(data["prev_digest"]),
            created_at=datetime.fromisoformat(created) if created else None,
        )


@dataclass(frozen=True)
class BatchWitness:
    """The leaf digests of a batch, retained off-chain.

    The commitment alone cannot say *which* record changed.  A root mismatch
    proves that something in the batch differs from what was anchored, but
    recovering the culprit requires the original per-record digests, and those
    are exactly what a Merkle root compresses away.

    The witness is therefore kept beside the ledger.  It is not authoritative
    and does not need to be trusted: :meth:`verify_against` rebuilds the root
    from it, so a witness that has itself been doctored is detected before it
    is used to accuse any record.  Losing the witness costs precision, not
    soundness -- interval and root checks still work without it.
    """

    batch_id: str
    sequences: tuple[int, ...]
    digests: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if len(self.sequences) != len(self.digests):
            raise ValueError("sequences and digests must be the same length")
        if not self.sequences:
            raise ValueError("a witness must cover at least one record")

    def __len__(self) -> int:
        return len(self.sequences)

    def digest_of(self, seq: int) -> bytes:
        """Anchored digest of the record with sequence number ``seq``."""
        try:
            return self.digests[self.sequences.index(seq)]
        except ValueError:
            raise KeyError(f"sequence {seq} is not in witness {self.batch_id!r}") from None

    def rebuild_root(self) -> bytes:
        return MerkleTree(self.digests).root

    def verify_against(self, commitment: BatchCommitment) -> bool:
        """Whether this witness reproduces the anchored commitment."""
        return (
            self.batch_id == commitment.batch_id
            and len(self.digests) == commitment.tree_size
            and self.rebuild_root() == commitment.root
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "sequences": list(self.sequences),
            "digests": [d.hex() for d in self.digests],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BatchWitness:
        return cls(
            batch_id=data["batch_id"],
            sequences=tuple(int(s) for s in data["sequences"]),
            digests=tuple(bytes.fromhex(d) for d in data["digests"]),
        )


@dataclass(frozen=True)
class Batch:
    """A built batch: its records, their digests, the tree and the commitment."""

    commitment: BatchCommitment
    schema: RecordSchema
    records: tuple[Mapping[str, Any], ...]
    digests: tuple[bytes, ...]
    tree: MerkleTree

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[Mapping[str, Any]]:
        return iter(self.records)

    @property
    def sequences(self) -> tuple[int, ...]:
        seq_field = self.schema.sequence_field
        assert seq_field is not None
        return tuple(int(r[seq_field]) for r in self.records)

    def index_of_sequence(self, seq: int) -> int:
        """Leaf index of the record with sequence number ``seq``."""
        try:
            return self.sequences.index(seq)
        except ValueError:
            # `from None`: the ValueError from list.index is an implementation
            # detail, and chaining it would put a confusing second traceback
            # in front of the message that actually explains the problem.
            raise KeyError(
                f"sequence {seq} is not in batch {self.commitment.batch_id!r}"
            ) from None

    def prove_sequence(self, seq: int):
        """Inclusion proof for the record with sequence number ``seq``."""
        return self.tree.prove(self.index_of_sequence(seq))

    def witness(self) -> BatchWitness:
        """The off-chain witness for this batch."""
        return BatchWitness(
            batch_id=self.commitment.batch_id,
            sequences=self.sequences,
            digests=self.digests,
        )


class BatchBuilder:
    """Accumulates records and seals them into a :class:`Batch`.

    Records must be added in ascending sequence order.  Out-of-order input
    would still produce a valid tree, but the leaf order would no longer
    match the sequence order, and every proof an auditor later reads would
    have to carry an explicit position mapping to be interpretable.
    """

    def __init__(
        self,
        schema: RecordSchema,
        batch_id: str,
        prev_digest: bytes = GENESIS_DIGEST,
    ) -> None:
        if schema.sequence_field is None:
            raise ValueError(
                f"schema {schema.schema_id!r} declares no sequence_field; "
                "interval commitments require one"
            )
        self.schema = schema
        self.batch_id = batch_id
        self.prev_digest = prev_digest
        self._records: list[Mapping[str, Any]] = []
        self._digests: list[bytes] = []
        self._sequences: list[int] = []

    def add(self, record: Mapping[str, Any]) -> int:
        """Add one record.  Returns its leaf index."""
        seq_field = self.schema.sequence_field
        assert seq_field is not None
        try:
            seq = int(record[seq_field])
        except KeyError:
            raise KeyError(f"record is missing sequence field {seq_field!r}") from None

        if self._sequences:
            if seq == self._sequences[-1]:
                raise ValueError(f"duplicate sequence number {seq}")
            if seq < self._sequences[-1]:
                raise ValueError(
                    f"sequence {seq} follows {self._sequences[-1]}; "
                    "records must be added in ascending order"
                )

        # record_digest validates the record against the schema, so a
        # malformed record is rejected here rather than at seal time.
        self._digests.append(record_digest(record, self.schema))
        self._records.append(dict(record))
        self._sequences.append(seq)
        return len(self._records) - 1

    def extend(self, records: Iterable[Mapping[str, Any]]) -> None:
        for record in records:
            self.add(record)

    def __len__(self) -> int:
        return len(self._records)

    def seal(self, created_at: datetime | None = None) -> Batch:
        """Build the Merkle tree and produce the commitment."""
        if not self._records:
            raise ValueError("cannot seal an empty batch")

        interval = Interval(
            first_seq=self._sequences[0],
            last_seq=self._sequences[-1],
            count=len(self._sequences),
        )
        tree = MerkleTree(self._digests)
        commitment = BatchCommitment(
            batch_id=self.batch_id,
            schema_id=self.schema.schema_id,
            schema_version=self.schema.version,
            interval=interval,
            root=tree.root,
            tree_size=len(tree),
            prev_digest=self.prev_digest,
            created_at=created_at or datetime.now(timezone.utc),
        )
        return Batch(
            commitment=commitment,
            schema=self.schema,
            records=tuple(self._records),
            digests=tuple(self._digests),
            tree=tree,
        )


@dataclass(frozen=True)
class IntervalFinding:
    """Result of checking observed records against a committed interval."""

    batch_id: str
    committed_count: int
    observed_count: int
    missing_sequences: tuple[int, ...]
    unexpected_sequences: tuple[int, ...]

    @property
    def missing_count(self) -> int:
        return self.committed_count - self.observed_count

    @property
    def intact(self) -> bool:
        return (
            self.observed_count == self.committed_count
            and not self.unexpected_sequences
        )


def check_interval(
    commitment: BatchCommitment,
    observed: Sequence[Mapping[str, Any]],
    schema: RecordSchema,
) -> IntervalFinding:
    """Compare records now present in a span against what was committed.

    ``observed`` should be every record the source currently holds whose
    sequence number falls inside the committed span.  A shortfall means
    records were removed; a surplus means records were inserted after
    anchoring, which is equally a violation of an append-only ledger.

    Sequence numbers cannot be listed individually as "missing" unless the
    original batch was dense, because a gap in a sparse batch is
    indistinguishable from a deletion by sequence number alone.  In that case
    the count shortfall is still reported, and the specific records are
    identified by replaying inclusion proofs instead.
    """
    seq_field = schema.sequence_field
    if seq_field is None:
        raise ValueError(f"schema {schema.schema_id!r} declares no sequence_field")

    interval = commitment.interval
    observed_seqs = sorted(int(r[seq_field]) for r in observed)

    # One pass, one comparison per record. The previous form tested each
    # sequence for membership in the ``in_span`` *list*, which made this
    # function quadratic in batch size: 0.3 s per 10,000-record batch, and
    # verification throughput fell by a third at the batch sizes the cost
    # guidance recommends (found by external audit of 0.6.7).
    in_span = [s for s in observed_seqs if interval.first_seq <= s <= interval.last_seq]
    unexpected = tuple(
        s for s in observed_seqs
        if not interval.first_seq <= s <= interval.last_seq
    )

    if interval.is_dense:
        expected = set(range(interval.first_seq, interval.last_seq + 1))
        missing = tuple(sorted(expected - set(in_span)))
        surplus = tuple(sorted(set(in_span) - expected))
    else:
        missing = ()
        surplus = ()

    return IntervalFinding(
        batch_id=commitment.batch_id,
        committed_count=interval.count,
        observed_count=len(in_span),
        missing_sequences=missing,
        unexpected_sequences=tuple(sorted(set(unexpected) | set(surplus))),
    )


def verify_chain(commitments: Sequence[BatchCommitment]) -> None:
    """Check that a sequence of commitments forms an unbroken hash chain.

    This is what makes deletion of a whole batch detectable: each commitment
    names its predecessor by digest, so a removed batch breaks the link
    between its neighbours even though both neighbours remain internally
    valid.

    Raises:
        ValueError: the chain is broken, or the first commitment is not a
            genesis commitment.
    """
    if not commitments:
        return

    if not commitments[0].is_genesis:
        raise ValueError(
            f"batch {commitments[0].batch_id!r} is not a genesis commitment; "
            "the chain does not start here"
        )

    for previous, current in pairwise(commitments):
        expected = previous.digest()
        if current.prev_digest != expected:
            raise ValueError(
                f"chain broken between {previous.batch_id!r} and "
                f"{current.batch_id!r}: expected predecessor "
                f"{expected.hex()[:16]}..., found "
                f"{current.prev_digest.hex()[:16]}..."
            )
