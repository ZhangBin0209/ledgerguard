"""Accounting profile: the double-entry journal.

This is the first domain profile over the generic record schema, and the one
that carries the semantics an auditor reasons about -- voucher numbering,
posting period, and debit/credit balance.  Those semantics are what let a
failed proof be reported in accounting terms ("voucher 000412 was deleted
from period 2026-03") rather than as an opaque hash mismatch.

A record here is one *line* of a journal entry.  Lines sharing a voucher
number form a document, and it is the document that must balance.
"""

from __future__ import annotations

from collections import defaultdict
from decimal import Decimal
from typing import Any, Iterable, Mapping, Sequence

from ..schema import FieldSpec, FieldType, RecordSchema

#: Schema for a single journal-entry line.
#:
#: ``line_seq`` is the globally monotonic sequence used for interval
#: commitments; ``voucher_no`` is the human-facing identifier, which in
#: practice is not reliably dense (voided vouchers leave gaps) and so cannot
#: carry the deletion-detection argument on its own.
JOURNAL_ENTRY_V1 = RecordSchema(
    schema_id="accounting.journal_entry",
    version=1,
    sequence_field="line_seq",
    fields=(
        FieldSpec("line_seq", FieldType.INTEGER),
        FieldSpec("voucher_no", FieldType.STRING),
        FieldSpec("line_no", FieldType.INTEGER),
        FieldSpec("period", FieldType.STRING),
        FieldSpec("posting_date", FieldType.DATE),
        FieldSpec("account_code", FieldType.STRING),
        FieldSpec("debit", FieldType.MONEY, scale=2),
        FieldSpec("credit", FieldType.MONEY, scale=2),
        FieldSpec("currency", FieldType.STRING),
        FieldSpec("description", FieldType.STRING, nullable=True),
        FieldSpec("preparer", FieldType.STRING),
        FieldSpec("document_ref", FieldType.STRING, nullable=True),
    ),
)


class BalanceError(ValueError):
    """A voucher's debits and credits do not agree."""


def _as_decimal(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, float):
        raise TypeError("float amounts are not accepted; use Decimal, int or str")
    return Decimal(str(value).strip())


def validate_line(record: Mapping[str, Any]) -> None:
    """Check the invariants that hold for a single line.

    A line carries an amount on exactly one side.  Both sides zero is a
    meaningless line; both sides non-zero is a malformed one.

    Raises:
        BalanceError: the line violates the one-sided rule.
    """
    debit = _as_decimal(record["debit"])
    credit = _as_decimal(record["credit"])

    if debit < 0 or credit < 0:
        raise BalanceError(
            f"line {record.get('line_seq')}: negative amounts are not permitted; "
            "reverse the side instead"
        )
    if debit == 0 and credit == 0:
        raise BalanceError(f"line {record.get('line_seq')}: both sides are zero")
    if debit != 0 and credit != 0:
        raise BalanceError(
            f"line {record.get('line_seq')}: both sides carry an amount"
        )


def validate_voucher_balance(lines: Iterable[Mapping[str, Any]]) -> None:
    """Check that each voucher balances, per currency.

    Grouping by currency matters: a voucher mixing currencies balances within
    each one, not across them, and summing the raw amounts together would
    mask a genuine imbalance.

    Raises:
        BalanceError: some voucher does not balance.
    """
    totals: dict[tuple[str, str], list[Decimal]] = defaultdict(
        lambda: [Decimal(0), Decimal(0)]
    )
    for line in lines:
        validate_line(line)
        key = (line["voucher_no"], line["currency"])
        totals[key][0] += _as_decimal(line["debit"])
        totals[key][1] += _as_decimal(line["credit"])

    for (voucher, currency), (debit, credit) in sorted(totals.items()):
        if debit != credit:
            raise BalanceError(
                f"voucher {voucher} ({currency}) does not balance: "
                f"debit {debit} vs credit {credit}"
            )


def sequence_interval(records: Sequence[Mapping[str, Any]]) -> tuple[int, int, int]:
    """Return ``(first_seq, last_seq, count)`` over ``line_seq``.

    This triple is the claim an interval commitment binds: a batch asserts
    that it contains exactly ``count`` records spanning ``first_seq`` to
    ``last_seq``.  Deleting a record leaves the count short of the span, and
    no digest needs to survive for that to be detectable -- which is the
    whole point, since a deleted record leaves nothing behind to re-hash.

    Raises:
        ValueError: ``records`` is empty or ``line_seq`` values repeat.
    """
    if not records:
        raise ValueError("cannot take an interval over an empty batch")

    seqs = [int(r["line_seq"]) for r in records]
    if len(set(seqs)) != len(seqs):
        duplicates = sorted({s for s in seqs if seqs.count(s) > 1})
        raise ValueError(f"duplicate line_seq values: {duplicates}")

    return min(seqs), max(seqs), len(seqs)


def is_dense(records: Sequence[Mapping[str, Any]]) -> bool:
    """Whether ``line_seq`` covers its interval with no gaps."""
    first, last, count = sequence_interval(records)
    return last - first + 1 == count
