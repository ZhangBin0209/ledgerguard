"""Accounting profile tests: domain invariants and interval commitments."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from ledgerguard.profiles.accounting import (
    JOURNAL_ENTRY_V1,
    BalanceError,
    is_dense,
    sequence_interval,
    validate_line,
    validate_voucher_balance,
)


def line(seq, voucher, line_no, debit="0.00", credit="0.00", currency="CNY"):
    return {
        "line_seq": seq,
        "voucher_no": voucher,
        "line_no": line_no,
        "period": "2026-03",
        "posting_date": date(2026, 3, 17),
        "account_code": "1001",
        "debit": Decimal(debit),
        "credit": Decimal(credit),
        "currency": currency,
        "description": None,
        "preparer": "chen.wei",
        "document_ref": None,
    }


def test_schema_declares_a_sequence_field():
    assert JOURNAL_ENTRY_V1.sequence_field == "line_seq"


def test_balanced_voucher_passes():
    validate_voucher_balance([
        line(1, "JV-1", 1, debit="500.00"),
        line(2, "JV-1", 2, credit="500.00"),
    ])


def test_unbalanced_voucher_is_rejected():
    with pytest.raises(BalanceError, match="does not balance"):
        validate_voucher_balance([
            line(1, "JV-1", 1, debit="500.00"),
            line(2, "JV-1", 2, credit="499.00"),
        ])


def test_balance_is_checked_per_currency():
    """A CNY debit does not offset a USD credit."""
    with pytest.raises(BalanceError, match="does not balance"):
        validate_voucher_balance([
            line(1, "JV-1", 1, debit="500.00", currency="CNY"),
            line(2, "JV-1", 2, credit="500.00", currency="USD"),
        ])


def test_vouchers_are_balanced_independently():
    with pytest.raises(BalanceError, match="JV-2"):
        validate_voucher_balance([
            line(1, "JV-1", 1, debit="500.00"),
            line(2, "JV-1", 2, credit="500.00"),
            line(3, "JV-2", 1, debit="300.00"),
        ])


@pytest.mark.parametrize("debit,credit", [("0.00", "0.00"), ("100.00", "100.00")])
def test_line_must_carry_exactly_one_side(debit, credit):
    with pytest.raises(BalanceError):
        validate_line(line(1, "JV-1", 1, debit=debit, credit=credit))


def test_negative_amounts_are_rejected():
    with pytest.raises(BalanceError, match="negative"):
        validate_line(line(1, "JV-1", 1, debit="-100.00"))


def test_interval_reports_span_and_count():
    records = [line(s, "JV-1", 1, debit="1.00") for s in (10, 11, 12, 13)]
    assert sequence_interval(records) == (10, 13, 4)
    assert is_dense(records)


def test_deletion_breaks_density():
    """The deletion-detection argument in one test.

    Nothing survives a deleted record to be re-hashed. What survives is the
    interval claim: four records spanning 10..13. Remove one and the count no
    longer fills the span.
    """
    records = [line(s, "JV-1", 1, debit="1.00") for s in (10, 11, 12, 13)]
    survivors = [r for r in records if r["line_seq"] != 12]
    assert sequence_interval(records) == (10, 13, 4)
    assert sequence_interval(survivors) == (10, 13, 3)
    assert is_dense(records)
    assert not is_dense(survivors)


def test_duplicate_sequence_numbers_are_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        sequence_interval([line(10, "JV-1", 1, debit="1.00"),
                           line(10, "JV-1", 2, credit="1.00")])


def test_empty_batch_has_no_interval():
    with pytest.raises(ValueError, match="empty"):
        sequence_interval([])
