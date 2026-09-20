"""Tamper injection with ground truth.

Detection rates are only meaningful against known ground truth, so every
injection here records exactly what it did.  The result is a labelled
dataset: a tampered ledger plus the list of records that were touched and
how, which is what lets a run compute recall per attack class rather than
report that "tampering was detected".

Four attack classes are implemented, chosen because they exercise different
parts of the commitment rather than because they exhaust the space:

``AMOUNT``
    A monetary value is changed in place.  Caught by the Merkle root; the
    canonical encoding is what makes the digest sensitive to it.

``DELETION``
    A record is removed entirely.  Leaves no digest to re-hash, so only the
    interval count sees it.

``PERIOD``
    A posting date and period are shifted across a reporting boundary --
    the classic cut-off manipulation.  The record still exists and still
    balances, so nothing but the digest reveals it.

``SEQUENCE``
    A record is inserted into an anchored span under a sequence number that
    is already anchored -- what an ``INSERT`` against a table without a
    unique constraint produces.  Caught as a duplicate by witness replay and
    as a count surplus by the interval check.  Note what this class does
    *not* cover: exchanging the sequence numbers of two records (which the
    verifier reports as two modifications) and inserting into an unused
    position of a sparse span (reported as an insertion, or as an orphan if
    it falls between batches).  Both are exercised by the unit tests but are
    not part of the benchmark.

An adversary model worth stating: the attacker has full write access to the
ledger database but cannot rewrite the chain.  Every injection below is
therefore something a database administrator could do silently.

This module is written against the accounting profile: it reads ``line_seq``,
``debit``, ``credit``, ``posting_date``, ``period`` and ``voucher_no`` by
name, because the manipulations it models -- an understated amount, a
posting moved across a period boundary -- only mean something in that
domain.  The provenance profile has no ground-truthed injector yet; its
domain rules are exercised by ``tests/test_provenance_profile.py``.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Sequence


class AttackClass(str, Enum):
    """The kind of manipulation applied to a record."""

    AMOUNT = "amount"
    DELETION = "deletion"
    PERIOD = "period"
    SEQUENCE = "sequence"


@dataclass(frozen=True)
class TamperEvent:
    """Ground truth for one injected manipulation."""

    attack: AttackClass
    sequence: int
    field_name: str | None = None
    before: Any = None
    after: Any = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack": self.attack.value,
            "sequence": self.sequence,
            "field": self.field_name,
            "before": str(self.before) if self.before is not None else None,
            "after": str(self.after) if self.after is not None else None,
            "detail": self.detail,
        }


@dataclass
class TamperLog:
    """The manipulations applied to a ledger, for scoring a detector."""

    events: list[TamperEvent] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self):
        return iter(self.events)

    def add(self, event: TamperEvent) -> None:
        self.events.append(event)

    def by_class(self, attack: AttackClass) -> tuple[TamperEvent, ...]:
        return tuple(e for e in self.events if e.attack is attack)

    @property
    def sequences(self) -> frozenset[int]:
        """Sequence numbers of every touched record."""
        return frozenset(e.sequence for e in self.events)

    def sequences_of(self, attack: AttackClass) -> frozenset[int]:
        return frozenset(e.sequence for e in self.by_class(attack))

    def counts(self) -> dict[str, int]:
        return {a.value: len(self.by_class(a)) for a in AttackClass}

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self.events),
            "counts": self.counts(),
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class TamperedLedger:
    """A manipulated ledger paired with its ground truth."""

    records: list[dict[str, Any]]
    log: TamperLog

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self):
        return iter(self.records)


def _seq(record: dict[str, Any]) -> int:
    return int(record["line_seq"])


def _pick(rng: random.Random, pool: list[int], n: int, taken: set[int]) -> list[int]:
    """Choose ``n`` untouched sequence numbers, or as many as remain."""
    available = [s for s in pool if s not in taken]
    n = min(n, len(available))
    chosen = rng.sample(available, n) if n else []
    taken.update(chosen)
    return sorted(chosen)


def inject(
    records: Sequence[dict[str, Any]],
    *,
    seed: int = 0,
    amount: int = 0,
    deletion: int = 0,
    period: int = 0,
    sequence: int = 0,
) -> TamperedLedger:
    """Apply a specified number of manipulations of each class.

    Each record is manipulated at most once.  Overlapping attacks on a single
    record would make the ground truth ambiguous -- a detector that flagged it
    could not be scored against any one class -- so the injector reserves each
    record it touches.

    Args:
        records: The clean ledger.  Not modified; a copy is returned.
        seed: Random seed, for reproducible injection.
        amount: Number of amount alterations.
        deletion: Number of records to delete.
        period: Number of cut-off manipulations.
        sequence: Number of sequence anomalies (insertions).

    Returns:
        The tampered ledger and the ground-truth log.
    """
    rng = random.Random(seed)
    working = [copy.deepcopy(r) for r in records]
    by_seq = {_seq(r): r for r in working}
    pool = sorted(by_seq)
    taken: set[int] = set()
    log = TamperLog()

    # --- amount alteration ------------------------------------------------
    for target in _pick(rng, pool, amount, taken):
        record = by_seq[target]
        side = "debit" if record["debit"] != Decimal("0.00") else "credit"
        before = record[side]
        # A round-number reduction: the shape of a real understatement, and
        # large enough that it would matter, not a rounding artefact.
        delta = (before * Decimal(rng.choice(("0.05", "0.10", "0.25")))).quantize(
            Decimal("1.00")
        )
        after = before - delta
        if after <= Decimal("0.00"):
            after = before + delta
        record[side] = after
        log.add(
            TamperEvent(
                attack=AttackClass.AMOUNT,
                sequence=target,
                field_name=side,
                before=before,
                after=after,
                detail=f"{side} altered by {after - before}",
            )
        )

    # --- cut-off manipulation ---------------------------------------------
    for target in _pick(rng, pool, period, taken):
        record = by_seq[target]
        before_date, before_period = record["posting_date"], record["period"]
        shift = rng.choice((-1, 1)) * rng.randint(20, 40)
        after_date = before_date + timedelta(days=shift)
        record["posting_date"] = after_date
        record["period"] = f"{after_date.year}-{after_date.month:02d}"
        log.add(
            TamperEvent(
                attack=AttackClass.PERIOD,
                sequence=target,
                field_name="posting_date",
                before=before_date,
                after=after_date,
                detail=f"period {before_period} -> {record['period']}",
            )
        )

    # --- sequence anomaly: insertion into an anchored span -----------------
    inserted: list[dict[str, Any]] = []
    for target in _pick(rng, pool, sequence, taken):
        template = by_seq[target]
        # A back-dated record squeezed in beside an existing one.  Fractional
        # sequence numbers are not available, so the insertion reuses a
        # sequence from the span and duplicates it, which is what an INSERT
        # without a unique constraint would produce.
        clone = copy.deepcopy(template)
        clone["voucher_no"] = f"{template['voucher_no']}-A"
        clone["description"] = "Backdated adjustment"
        clone["debit"] = template["debit"]
        clone["credit"] = template["credit"]
        inserted.append(clone)
        log.add(
            TamperEvent(
                attack=AttackClass.SEQUENCE,
                sequence=target,
                field_name="line_seq",
                before=target,
                after=target,
                detail="duplicate record inserted at an anchored sequence",
            )
        )

    # --- deletion (applied last, so earlier attacks keep their targets) ----
    deleted = set(_pick(rng, pool, deletion, taken))
    for target in sorted(deleted):
        record = by_seq[target]
        log.add(
            TamperEvent(
                attack=AttackClass.DELETION,
                sequence=target,
                detail=f"voucher {record['voucher_no']} line removed",
            )
        )

    survivors = [r for r in working if _seq(r) not in deleted]
    survivors.extend(inserted)
    survivors.sort(key=lambda r: (_seq(r), r["voucher_no"]))
    return TamperedLedger(records=survivors, log=log)


def inject_proportional(
    records: Sequence[dict[str, Any]],
    *,
    rate: float = 0.01,
    seed: int = 0,
) -> TamperedLedger:
    """Inject manipulations at a given rate, spread evenly across classes.

    Args:
        records: The clean ledger.
        rate: Fraction of records to manipulate in total.
        seed: Random seed.
    """
    if not 0.0 <= rate <= 1.0:
        raise ValueError("rate must lie in [0, 1]")
    total = max(len(AttackClass), round(len(records) * rate))
    per_class, remainder = divmod(total, len(AttackClass))
    counts = [per_class + (1 if i < remainder else 0) for i in range(len(AttackClass))]
    return inject(
        records,
        seed=seed,
        amount=counts[0],
        deletion=counts[1],
        period=counts[2],
        sequence=counts[3],
    )
