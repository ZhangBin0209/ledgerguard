"""Synthetic ledger generation.

Integrity research on accounting data has an obvious obstacle: real journals
are confidential, so published evaluations rest on private datasets and
cannot be reproduced or compared.  This module removes the obstacle by
generating ledgers that carry the structural properties tamper detection
actually depends on -- balanced vouchers, monotonic sequences, realistic gaps
from voided documents, period boundaries -- without carrying any real data.

Generation is seeded and deterministic: the same seed and parameters yield a
byte-identical ledger on any machine and any Python build, so a reported
detection rate can be re-derived rather than taken on trust.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Iterator, Sequence

from .profiles.accounting import JOURNAL_ENTRY_V1
from .profiles.provenance import (
    ARTIFACT_WRITTEN,
    CALIBRATION,
    INSTRUMENT_EVENT_V1,
    MEASUREMENT,
    RUN_END,
    RUN_START,
    SAMPLE_LOADED,
)
from .schema import RecordSchema

#: Account codes drawn on for the debit and credit sides.
DEBIT_ACCOUNTS = ("1001", "1002", "1122", "1601", "1801", "5101", "5601", "6602")
CREDIT_ACCOUNTS = ("1001", "1002", "2202", "2211", "2221", "4001", "6001")

DESCRIPTIONS = (
    "Petty cash replenishment",
    "Supplier payment",
    "Travel reimbursement",
    "Utilities settlement",
    "Equipment purchase",
    "Payroll accrual",
    "Service revenue",
    "Consumables purchase",
    "Freight charge",
    "Consulting fee",
)

PREPARERS = ("chen.wei", "li.hua", "wang.min", "zhao.lei", "sun.yan")

CURRENCIES = ("CNY", "CNY", "CNY", "CNY", "USD")  # weighted toward CNY


@dataclass(frozen=True)
class LedgerSpec:
    """Parameters controlling a generated ledger.

    Attributes:
        vouchers: Number of vouchers to generate.  Each yields two or more
            lines, so the record count is a small multiple of this.
        seed: Random seed.  Fixing it makes the ledger reproducible.
        start_date: Posting date of the first voucher.
        batch_size: Records per batch when the ledger is split for anchoring.
        void_rate: Fraction of voucher numbers that are burned without
            producing records, simulating voided documents.  These are what
            make real batches sparse, and a detector that assumes density
            fails on the first day of production use.
        multi_line_rate: Fraction of vouchers carrying more than two lines.
        max_extra_lines: Upper bound on additional line pairs for those.
        foreign_currency_rate: Fraction of vouchers posted in USD.
    """

    vouchers: int = 100
    seed: int = 0
    start_date: date = date(2026, 1, 1)
    batch_size: int = 50
    void_rate: float = 0.03
    multi_line_rate: float = 0.15
    max_extra_lines: int = 2
    foreign_currency_rate: float = 0.05

    def __post_init__(self) -> None:
        if self.vouchers < 1:
            raise ValueError("vouchers must be positive")
        if self.batch_size < 1:
            raise ValueError("batch_size must be positive")
        for name in ("void_rate", "multi_line_rate", "foreign_currency_rate"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must lie in [0, 1]")


@dataclass
class SyntheticLedger:
    """A generated ledger and the parameters that produced it."""

    spec: LedgerSpec
    schema: RecordSchema
    records: list[dict[str, Any]] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.records)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.records[index]

    @property
    def sequences(self) -> tuple[int, ...]:
        """Sequence numbers, read through the schema rather than by name.

        Reading ``line_seq`` directly would have quietly tied the generator to
        the accounting profile -- the kind of leak that makes a two-layer
        design real only on paper.
        """
        field = self.schema.sequence_field
        assert field is not None
        return tuple(int(r[field]) for r in self.records)

    def batches(self) -> list[list[dict[str, Any]]]:
        """Split into fixed-size batches for anchoring."""
        size = self.spec.batch_size
        return [
            self.records[i : i + size] for i in range(0, len(self.records), size)
        ]

    def copy(self) -> SyntheticLedger:
        """A deep-enough copy that tampering does not touch the original."""
        return SyntheticLedger(
            spec=self.spec,
            schema=self.schema,
            records=[dict(r) for r in self.records],
        )


def _amount(rng: random.Random) -> Decimal:
    """A plausible transaction amount, quantised to two decimal places."""
    magnitude = rng.choice((2, 2, 3, 3, 3, 4, 4, 5))
    raw = rng.randint(10 ** (magnitude - 1), 10**magnitude - 1)
    cents = rng.choice((0, 0, 0, 50, 25, 99, rng.randint(1, 99)))
    return Decimal(raw) + Decimal(cents) / 100


def generate(spec: LedgerSpec | None = None, **kwargs: Any) -> SyntheticLedger:
    """Generate a reproducible synthetic journal.

    Every voucher balances by construction, sequence numbers increase
    monotonically, and voided vouchers leave gaps in the voucher numbering
    without disturbing the line sequence -- which is exactly the situation
    that makes voucher numbers unusable for deletion detection and forces the
    separate ``line_seq`` field.
    """
    spec = spec or LedgerSpec(**kwargs)
    rng = random.Random(spec.seed)
    ledger = SyntheticLedger(spec=spec, schema=JOURNAL_ENTRY_V1)

    line_seq = 1
    voucher_number = 1
    posting = spec.start_date

    for _ in range(spec.vouchers):
        # Burn voucher numbers for voided documents.  The line sequence is
        # untouched: nothing was posted, so nothing was sequenced.
        while rng.random() < spec.void_rate:
            voucher_number += 1

        if rng.random() < 0.35:
            posting += timedelta(days=rng.randint(1, 3))

        currency = "USD" if rng.random() < spec.foreign_currency_rate else "CNY"
        voucher_no = f"JV-{posting.year}-{voucher_number:06d}"
        period = f"{posting.year}-{posting.month:02d}"
        preparer = rng.choice(PREPARERS)
        description = rng.choice(DESCRIPTIONS)

        pairs = 1
        if rng.random() < spec.multi_line_rate:
            pairs += rng.randint(1, spec.max_extra_lines)

        line_no = 1
        for _ in range(pairs):
            amount = _amount(rng)
            for side, accounts in (
                ("debit", DEBIT_ACCOUNTS),
                ("credit", CREDIT_ACCOUNTS),
            ):
                ledger.records.append(
                    {
                        "line_seq": line_seq,
                        "voucher_no": voucher_no,
                        "line_no": line_no,
                        "period": period,
                        "posting_date": posting,
                        "account_code": rng.choice(accounts),
                        "debit": amount if side == "debit" else Decimal("0.00"),
                        "credit": amount if side == "credit" else Decimal("0.00"),
                        "currency": currency,
                        "description": description if line_no == 1 else None,
                        "preparer": preparer,
                        "document_ref": (
                            f"REQ-{rng.randint(1000, 9999)}"
                            if rng.random() < 0.6
                            else None
                        ),
                    }
                )
                line_seq += 1
                line_no += 1

        voucher_number += 1

    return ledger


def group_by_voucher(
    records: Sequence[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Group lines by voucher number, preserving line order."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        grouped.setdefault(record["voucher_no"], []).append(record)
    return grouped


# --------------------------------------------------------------------------
# Provenance ledgers
#
# The second generator exists for the same reason as the second profile: to
# demonstrate that the pipeline is not accounting-shaped. It produces runs
# that satisfy the provenance invariants -- chronologically ordered, calibrated
# before measured -- so that any violation a verifier reports is attributable
# to injected tampering rather than to sloppy generation.
# --------------------------------------------------------------------------

INSTRUMENTS = ("LC-MS-01", "LC-MS-02", "NMR-600", "SEM-04", "SEQ-11")
OPERATORS = ("m.torres", "k.nakamura", "a.osei", "p.novak")


def generate_provenance(
    runs: int = 50,
    seed: int = 0,
    batch_size: int = 100,
    start: datetime | None = None,
) -> SyntheticLedger:
    """Generate a reproducible ledger of instrument-run events.

    Each run opens, loads a sample, calibrates, measures one or more times,
    writes an artefact and closes. Timestamps advance monotonically and are
    timezone-aware, which exercises the UTC normalisation path the accounting
    profile never touches.
    """
    rng = random.Random(seed)
    clock = start or datetime(2026, 2, 3, 8, 0, tzinfo=timezone.utc)
    ledger = SyntheticLedger(
        spec=LedgerSpec(vouchers=runs, seed=seed, batch_size=batch_size),
        schema=INSTRUMENT_EVENT_V1,
    )

    event_seq = 1
    for run_index in range(runs):
        run_id = f"RUN-2026-{run_index + 1:05d}"
        instrument = rng.choice(INSTRUMENTS)
        operator = rng.choice(OPERATORS)
        sample_id = f"S-{rng.randint(10_000, 99_999)}"
        clock += timedelta(minutes=rng.randint(15, 240))

        # Bound explicitly rather than captured: the closure is only ever
        # called within this iteration, but relying on that is the kind of
        # thing that breaks the moment someone defers a call.
        def event(kind, sample=None, digest=None, params=None,
                  _run=run_id, _inst=instrument, _op=operator):
            nonlocal event_seq, clock
            clock += timedelta(seconds=rng.randint(30, 900))
            record = {
                "event_seq": event_seq,
                "run_id": _run,
                "event_type": kind,
                "recorded_at": clock,
                "instrument_id": _inst,
                "operator": _op,
                "sample_id": sample,
                "artifact_digest": digest,
                "parameters": params,
                "is_automated": kind in (CALIBRATION, ARTIFACT_WRITTEN),
            }
            event_seq += 1
            return record

        ledger.records.append(event(RUN_START))
        ledger.records.append(event(SAMPLE_LOADED, sample=sample_id))
        ledger.records.append(
            event(CALIBRATION, params=f"gain={rng.randint(1, 9)}")
        )
        for _ in range(rng.randint(1, 4)):
            ledger.records.append(
                event(
                    MEASUREMENT,
                    sample=sample_id,
                    params=f"scans={rng.choice((8, 16, 32, 64))}",
                )
            )
        ledger.records.append(
            event(
                ARTIFACT_WRITTEN,
                digest=hashlib.sha256(
                    f"{run_id}-{rng.random()}".encode()
                ).hexdigest(),
            )
        )
        ledger.records.append(event(RUN_END))

    return ledger
