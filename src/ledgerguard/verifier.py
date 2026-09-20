"""Verification: turning cryptographic mismatches into audit findings.

An auditor does not want a root hash comparison.  They want to know which
voucher changed, what it changed from, and what evidence supports the claim.
This module produces that: a per-record verdict backed by an inclusion proof
or by a shortfall against a committed count.

Three checks run, in order of decreasing precision:

1.  **Witness replay** names the individual records that were modified,
    deleted or inserted.  Requires the off-chain witness.
2.  **Root comparison** proves that *something* in the batch differs from what
    was anchored, without saying what.  Requires only the observed records.
3.  **Interval check** catches deletions and insertions from the record count
    alone.  Survives the loss of both the witness and the record contents.

Each is strictly weaker than the one above and strictly more robust to
missing evidence, so a verification run degrades rather than fails when part
of the off-chain material is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from .backends import ChainBackend
from .canonical import record_digest
from .commitment import BatchCommitment, BatchWitness, IntervalFinding, check_interval
from .merkle import InclusionProof, MerkleTree
from .schema import RecordSchema


class Verdict(str, Enum):
    """Outcome for a single record."""

    INTACT = "intact"
    MODIFIED = "modified"
    DELETED = "deleted"
    INSERTED = "inserted"


class BatchStatus(str, Enum):
    """Outcome for a whole batch."""

    INTACT = "intact"
    TAMPERED = "tampered"
    NOT_ANCHORED = "not_anchored"
    WITNESS_INVALID = "witness_invalid"
    SCHEMA_MISMATCH = "schema_mismatch"


@dataclass(frozen=True)
class RecordFinding:
    """What happened to one record, and the evidence for saying so."""

    sequence: int
    verdict: Verdict
    anchored_digest: bytes | None = None
    observed_digest: bytes | None = None
    leaf_index: int | None = None
    proof: InclusionProof | None = None
    detail: str = ""

    @property
    def is_finding(self) -> bool:
        return self.verdict is not Verdict.INTACT

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "verdict": self.verdict.value,
            "anchored_digest": self.anchored_digest.hex() if self.anchored_digest else None,
            "observed_digest": self.observed_digest.hex() if self.observed_digest else None,
            "leaf_index": self.leaf_index,
            "proof_path": [h.hex() for h in self.proof.path] if self.proof else None,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class BatchReport:
    """Verification outcome for one anchored batch."""

    batch_id: str
    status: BatchStatus
    commitment: BatchCommitment | None = None
    anchored_root: bytes | None = None
    observed_root: bytes | None = None
    interval: IntervalFinding | None = None
    findings: tuple[RecordFinding, ...] = ()
    detail: str = ""

    @property
    def intact(self) -> bool:
        return self.status is BatchStatus.INTACT

    @property
    def root_matches(self) -> bool | None:
        if self.anchored_root is None or self.observed_root is None:
            return None
        return self.anchored_root == self.observed_root

    def by_verdict(self, verdict: Verdict) -> tuple[RecordFinding, ...]:
        return tuple(f for f in self.findings if f.verdict is verdict)

    @property
    def tampered_records(self) -> tuple[RecordFinding, ...]:
        return tuple(f for f in self.findings if f.is_finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "status": self.status.value,
            "anchored_root": self.anchored_root.hex() if self.anchored_root else None,
            "observed_root": self.observed_root.hex() if self.observed_root else None,
            "root_matches": self.root_matches,
            "committed_count": self.interval.committed_count if self.interval else None,
            "observed_count": self.interval.observed_count if self.interval else None,
            "findings": [f.to_dict() for f in self.tampered_records],
            "detail": self.detail,
        }


@dataclass(frozen=True)
class LedgerReport:
    """Verification outcome across every anchored batch.

    Attributes:
        orphan_sequences: Records present in the ledger whose sequence falls
            inside no anchored span. Routing by span would otherwise drop
            them silently, which is exactly what an intruder inserting between
            two batch boundaries would rely on.
    """

    batches: tuple[BatchReport, ...]
    chain_intact: bool
    chain_detail: str = ""
    orphan_sequences: tuple[int, ...] = ()

    @property
    def intact(self) -> bool:
        return (
            self.chain_intact
            and not self.orphan_sequences
            and all(b.intact for b in self.batches)
        )

    @property
    def tampered_batches(self) -> tuple[BatchReport, ...]:
        return tuple(b for b in self.batches if not b.intact)

    def count(self, verdict: Verdict) -> int:
        return sum(len(b.by_verdict(verdict)) for b in self.batches)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "chain_intact": self.chain_intact,
            "chain_detail": self.chain_detail,
            "totals": {v.value: self.count(v) for v in Verdict},
            "orphan_sequences": list(self.orphan_sequences),
            "batches": [b.to_dict() for b in self.batches],
        }

    def summary(self) -> str:
        """A short human-readable verdict."""
        if self.intact:
            return f"{len(self.batches)} batches verified; no discrepancies"
        mismatched = [b for b in self.batches
                      if b.status is BatchStatus.SCHEMA_MISMATCH]
        if mismatched:
            return (
                f"{len(mismatched)} of {len(self.batches)} batches were anchored "
                "under a different schema; check the --profile and the anchor file"
            )

        parts = []
        if not self.chain_intact:
            parts.append(f"chain broken ({self.chain_detail})")
        for verdict in (Verdict.MODIFIED, Verdict.DELETED, Verdict.INSERTED):
            n = self.count(verdict)
            if n:
                parts.append(f"{n} {verdict.value}")

        # Batches checked without a witness carry only interval and root
        # evidence. That evidence used to vanish from this line -- a five-
        # record shortfall was summarised as "root mismatch without
        # record-level attribution" -- which understates the finding on the
        # one line a scheduled job reads first.
        short = surplus = roots = 0
        for batch in self.batches:
            if batch.status is not BatchStatus.TAMPERED or batch.findings:
                continue
            if batch.interval is None:
                continue
            gap = batch.interval.missing_count
            if gap > 0:
                short += gap
            elif gap < 0:
                surplus += -gap
            else:
                roots += 1
        if short:
            parts.append(f"{short} missing against committed counts")
        if surplus:
            parts.append(f"{surplus} present beyond committed counts")
        if roots:
            parts.append(
                f"{roots} {'batch' if roots == 1 else 'batches'} with a root "
                "mismatch and no witness to attribute it"
            )

        invalid = sum(1 for b in self.batches
                      if b.status is BatchStatus.WITNESS_INVALID)
        if invalid:
            parts.append(f"{invalid} witness{'' if invalid == 1 else 'es'} rejected")
        unanchored = sum(1 for b in self.batches
                         if b.status is BatchStatus.NOT_ANCHORED)
        if unanchored:
            parts.append(f"{unanchored} not anchored")

        if self.orphan_sequences:
            parts.append(
                f"{len(self.orphan_sequences)} outside every anchored range"
            )
        if not parts:
            parts.append("root mismatch without record-level attribution")
        return "; ".join(parts)


class Verifier:
    """Checks observed ledger records against anchored commitments."""

    def __init__(self, backend: ChainBackend, schema: RecordSchema) -> None:
        if schema.sequence_field is None:
            raise ValueError(
                f"schema {schema.schema_id!r} declares no sequence_field"
            )
        self.backend = backend
        self.schema = schema

    @property
    def _seq_field(self) -> str:
        assert self.schema.sequence_field is not None
        return self.schema.sequence_field

    def _sequence_of(self, record: Mapping[str, Any]) -> int:
        return int(record[self._seq_field])

    def _digest(self, record: Mapping[str, Any]) -> bytes | None:
        """Digest of a record, or ``None`` if it no longer parses.

        A record that fails canonicalisation is itself a finding: some field
        now holds a value the schema does not admit.  Refusing to verify the
        whole batch because of one malformed row would hide the rest.
        """
        try:
            return record_digest(record, self.schema)
        except (KeyError, ValueError, TypeError):
            return None

    def verify_batch(
        self,
        batch_id: str,
        observed: Sequence[Mapping[str, Any]],
        witness: BatchWitness | None = None,
    ) -> BatchReport:
        """Verify the records currently present for one anchored batch.

        Fetches the anchor itself. When a caller already holds the
        commitment -- as :meth:`verify_ledger` does for every batch it
        checks -- call :meth:`_verify_commitment` directly instead: on
        :class:`~ledgerguard.backends.FileBackend`, ``fetch`` re-reads the
        whole anchor file, and calling it once per batch turned checking an
        N-batch ledger into an O(N^2) file scan.
        """
        anchor = self.backend.fetch(batch_id)
        if anchor is None:
            return BatchReport(
                batch_id=batch_id,
                status=BatchStatus.NOT_ANCHORED,
                detail="no anchor exists for this batch id",
            )
        return self._verify_commitment(anchor.commitment, observed, witness)

    def _verify_commitment(
        self,
        commitment: BatchCommitment,
        observed: Sequence[Mapping[str, Any]],
        witness: BatchWitness | None = None,
    ) -> BatchReport:
        """The verification logic proper, given a commitment already in hand."""
        batch_id = commitment.batch_id

        # Verifying against an anchor built for a different schema would
        # report every record as modified -- technically true, and completely
        # useless. The commitment records the schema it was built for
        # precisely so the mismatch can be named instead.
        if (commitment.schema_id, commitment.schema_version) != (
            self.schema.schema_id,
            self.schema.version,
        ):
            return BatchReport(
                batch_id=batch_id,
                status=BatchStatus.SCHEMA_MISMATCH,
                commitment=commitment,
                anchored_root=commitment.root,
                detail=(
                    f"anchored under {commitment.schema_id} v"
                    f"{commitment.schema_version}, but verification was "
                    f"requested with {self.schema.schema_id} v"
                    f"{self.schema.version}"
                ),
            )

        ordered = sorted(observed, key=self._sequence_of)
        interval = check_interval(commitment, ordered, self.schema)
        observed_root = MerkleTree(
            [d for d in (self._digest(r) for r in ordered) if d is not None]
        ).root if ordered else None

        if witness is None:
            return self._report_without_witness(
                commitment, interval, observed_root
            )

        if not witness.verify_against(commitment):
            return BatchReport(
                batch_id=batch_id,
                status=BatchStatus.WITNESS_INVALID,
                commitment=commitment,
                anchored_root=commitment.root,
                observed_root=observed_root,
                interval=interval,
                detail=(
                    "the witness does not reproduce the anchored root; it cannot "
                    "be used to attribute findings to individual records"
                ),
            )

        findings = self._replay_witness(witness, ordered)
        tampered = [f for f in findings if f.is_finding]
        return BatchReport(
            batch_id=batch_id,
            status=BatchStatus.INTACT if not tampered else BatchStatus.TAMPERED,
            commitment=commitment,
            anchored_root=commitment.root,
            observed_root=observed_root,
            interval=interval,
            findings=tuple(findings),
            detail="" if not tampered else f"{len(tampered)} records differ from the anchor",
        )

    def _report_without_witness(
        self,
        commitment: BatchCommitment,
        interval: IntervalFinding,
        observed_root: bytes | None,
    ) -> BatchReport:
        """Fall back to root and interval evidence when no witness is held."""
        root_matches = observed_root == commitment.root
        if root_matches and interval.intact:
            status, detail = BatchStatus.INTACT, ""
        elif not interval.intact:
            status = BatchStatus.TAMPERED
            shortfall = interval.missing_count
            detail = (
                f"{shortfall} records missing against the committed count"
                if shortfall > 0
                else f"{-shortfall} records present beyond the committed count"
            )
        else:
            status = BatchStatus.TAMPERED
            detail = (
                "root mismatch: the batch differs from what was anchored, but "
                "no witness is available to identify which records"
            )
        return BatchReport(
            batch_id=commitment.batch_id,
            status=status,
            commitment=commitment,
            anchored_root=commitment.root,
            observed_root=observed_root,
            interval=interval,
            detail=detail,
        )

    def _replay_witness(
        self, witness: BatchWitness, ordered: Sequence[Mapping[str, Any]]
    ) -> list[RecordFinding]:
        """Compare each anchored digest against what the ledger holds now.

        Observed records are grouped into lists rather than a flat mapping,
        because an insertion attack typically produces a *duplicate* sequence
        number -- an ``INSERT`` against a table without a unique constraint.
        Keying by sequence alone would let the intruding row silently displace
        the genuine one, which would be reported as a modification and would
        leave the insertion itself invisible.
        """
        tree = MerkleTree(witness.digests)
        observed_by_seq: dict[int, list[Mapping[str, Any]]] = {}
        for record in ordered:
            observed_by_seq.setdefault(self._sequence_of(record), []).append(record)

        findings: list[RecordFinding] = []

        # strict=True: BatchWitness already guarantees equal lengths, and a
        # silent truncation here would drop records from the comparison
        # entirely -- they would be reported as neither intact nor missing.
        for index, (seq, anchored) in enumerate(
            zip(witness.sequences, witness.digests, strict=True)
        ):
            candidates = observed_by_seq.pop(seq, [])
            if not candidates:
                findings.append(
                    RecordFinding(
                        sequence=seq,
                        verdict=Verdict.DELETED,
                        anchored_digest=anchored,
                        leaf_index=index,
                        proof=tree.prove(index),
                        detail="anchored but no longer present in the ledger",
                    )
                )
                continue

            digests = [self._digest(r) for r in candidates]
            # If any row at this sequence still matches the anchor, that row
            # is the genuine record and the rest are intruders.
            if anchored in digests:
                match = digests.index(anchored)
                findings.append(
                    RecordFinding(
                        sequence=seq,
                        verdict=Verdict.INTACT,
                        anchored_digest=anchored,
                        observed_digest=anchored,
                        leaf_index=index,
                        proof=tree.prove(index),
                    )
                )
                extras = [d for i, d in enumerate(digests) if i != match]
            else:
                findings.append(
                    RecordFinding(
                        sequence=seq,
                        verdict=Verdict.MODIFIED,
                        anchored_digest=anchored,
                        observed_digest=digests[0],
                        leaf_index=index,
                        proof=tree.prove(index),
                        detail=(
                            "the record no longer satisfies its schema"
                            if digests[0] is None
                            else "content differs from the anchored digest"
                        ),
                    )
                )
                extras = digests[1:]

            for extra in extras:
                findings.append(
                    RecordFinding(
                        sequence=seq,
                        verdict=Verdict.INSERTED,
                        anchored_digest=anchored,
                        observed_digest=extra,
                        leaf_index=index,
                        detail="a second record shares an anchored sequence number",
                    )
                )

        for seq in sorted(observed_by_seq):
            for record in observed_by_seq[seq]:
                findings.append(
                    RecordFinding(
                        sequence=seq,
                        verdict=Verdict.INSERTED,
                        observed_digest=self._digest(record),
                        detail="present in the ledger but absent from the anchor",
                    )
                )
        return findings

    def verify_ledger(
        self,
        observed: Iterable[Mapping[str, Any]],
        witnesses: Mapping[str, BatchWitness] | None = None,
    ) -> LedgerReport:
        """Verify every anchored batch against the ledger as it stands now.

        Records are routed to batches by sequence span. A record whose
        sequence falls inside no anchored span is reported separately as an
        orphan rather than dropped: an intruder who inserts between two batch
        boundaries would otherwise be invisible to span-based routing, which
        is the one place this scheme could be walked around.
        """
        from bisect import bisect_left, bisect_right

        from .commitment import verify_chain

        witnesses = witnesses or {}
        records = sorted(observed, key=self._sequence_of)
        # A parallel array of sequence numbers, so each batch's records can be
        # located by binary search rather than by scanning every record for
        # every batch. `records` is already sorted, so this costs nothing
        # extra to build and turns routing from O(batches x records) into
        # O(batches x log(records)) -- the difference between a few
        # milliseconds and several seconds once a ledger has a few thousand
        # batches. Duplicate sequence numbers (an insertion attack) are
        # unaffected: bisect on a sorted array with repeats still returns the
        # full contiguous run of a value.
        seqs = [self._sequence_of(r) for r in records]
        commitments = list(self.backend.chain())

        chain_intact, chain_detail = True, ""
        try:
            verify_chain(commitments)
        except ValueError as exc:
            chain_intact, chain_detail = False, str(exc)

        reports = []
        routed: set[int] = set()
        for commitment in commitments:
            span = commitment.interval
            lo = bisect_left(seqs, span.first_seq)
            hi = bisect_right(seqs, span.last_seq)
            in_span = records[lo:hi]
            routed.update(seqs[lo:hi])
            # _verify_commitment, not verify_batch: `commitments` already came
            # from one call to backend.chain(), so re-deriving each one via
            # fetch(batch_id) would be a second, redundant lookup -- on
            # FileBackend specifically, one that re-reads the whole file.
            reports.append(
                self._verify_commitment(
                    commitment,
                    in_span,
                    witnesses.get(commitment.batch_id),
                )
            )

        # Deliberately *not* conditional on any anchors existing. With no
        # commitments every record is outside every anchored span, and the
        # ledger is therefore not intact -- a verifier that answers "no
        # discrepancies" when it has nothing to compare against is the one
        # result a scheduled job must never be able to produce (found by
        # external audit of 0.6.7: a deleted or mislocated anchor store
        # verified clean).
        orphans = sorted(set(seqs) - routed)

        return LedgerReport(
            batches=tuple(reports),
            chain_intact=chain_intact,
            chain_detail=chain_detail,
            orphan_sequences=tuple(orphans),
        )


def format_report(report: LedgerReport, max_findings: int = 20) -> str:
    """Render a ledger report as plain text for a console or an appendix."""
    lines = [f"Verification summary: {report.summary()}", ""]
    for batch in report.batches:
        marker = "OK  " if batch.intact else "FAIL"
        lines.append(f"[{marker}] {batch.batch_id}  ({batch.status.value})")
        if batch.interval:
            lines.append(
                f"        committed {batch.interval.committed_count} records, "
                f"observed {batch.interval.observed_count}"
            )
        if batch.detail:
            lines.append(f"        {batch.detail}")
        for finding in batch.tampered_records[:max_findings]:
            lines.append(
                f"        seq {finding.sequence}: {finding.verdict.value}"
                + (f" -- {finding.detail}" if finding.detail else "")
            )
        remaining = len(batch.tampered_records) - max_findings
        if remaining > 0:
            lines.append(f"        ... and {remaining} more")
    if report.orphan_sequences:
        shown = ", ".join(str(s) for s in report.orphan_sequences[:max_findings])
        more = len(report.orphan_sequences) - max_findings
        lines += [
            "",
            f"Outside every anchored range ({len(report.orphan_sequences)} "
            f"records): {shown}" + (f", ... and {more} more" if more > 0 else ""),
        ]
    if not report.chain_intact:
        lines += ["", f"Chain: {report.chain_detail}"]
    return "\n".join(lines)
