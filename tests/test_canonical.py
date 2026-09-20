"""Canonicalisation tests.

Two properties are under test throughout:

*   **Stability** -- representational differences that do not change the
    meaning of a record must not change its digest.
*   **Sensitivity** -- any change to the meaning must change the digest.

Every test below belongs to one of those two families.
"""

from __future__ import annotations

import unicodedata
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from ledgerguard import (
    FieldSpec,
    FieldType,
    RecordSchema,
    canonical_preimage,
    record_digest,
)
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1


def entry(**overrides):
    base = {
        "line_seq": 1041,
        "voucher_no": "JV-2026-000412",
        "line_no": 1,
        "period": "2026-03",
        "posting_date": date(2026, 3, 17),
        "account_code": "1001",
        "debit": Decimal("1250.00"),
        "credit": Decimal("0.00"),
        "currency": "CNY",
        "description": "Petty cash replenishment",
        "preparer": "chen.wei",
        "document_ref": "REQ-8871",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# Stability: same meaning, same digest
# --------------------------------------------------------------------------


def test_field_order_is_irrelevant():
    forward = entry()
    reversed_order = dict(reversed(list(forward.items())))
    assert record_digest(forward, JOURNAL_ENTRY_V1) == record_digest(
        reversed_order, JOURNAL_ENTRY_V1
    )


@pytest.mark.parametrize(
    "amount",
    [Decimal("1250.00"), Decimal("1250.0"), Decimal("1250"), 1250, "1250.00", "1250"],
)
def test_money_representations_agree(amount):
    """The same amount written six ways must hash identically."""
    assert record_digest(entry(debit=amount), JOURNAL_ENTRY_V1) == record_digest(
        entry(debit=Decimal("1250.00")), JOURNAL_ENTRY_V1
    )


def test_date_accepts_iso_string_and_object():
    assert record_digest(
        entry(posting_date="2026-03-17"), JOURNAL_ENTRY_V1
    ) == record_digest(entry(posting_date=date(2026, 3, 17)), JOURNAL_ENTRY_V1)


def test_string_whitespace_is_stripped():
    assert record_digest(
        entry(preparer="  chen.wei  "), JOURNAL_ENTRY_V1
    ) == record_digest(entry(preparer="chen.wei"), JOURNAL_ENTRY_V1)


def test_unicode_normalisation_forms_agree():
    """NFD and NFC spellings of the same text are the same text."""
    nfc = "Café"
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfc != nfd  # different code points
    assert record_digest(entry(description=nfd), JOURNAL_ENTRY_V1) == record_digest(
        entry(description=nfc), JOURNAL_ENTRY_V1
    )


def test_datetime_offsets_normalise_to_utc():
    schema = RecordSchema(
        schema_id="test.event",
        version=1,
        fields=(FieldSpec("at", FieldType.DATETIME),),
    )
    utc = datetime(2026, 3, 17, 4, 0, 0, tzinfo=timezone.utc)
    shanghai = datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone(timedelta(hours=8)))
    assert record_digest({"at": utc}, schema) == record_digest(
        {"at": shanghai}, schema
    )


# --------------------------------------------------------------------------
# Sensitivity: different meaning, different digest
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("line_seq", 1042),
        ("voucher_no", "JV-2026-000413"),
        ("line_no", 2),
        ("period", "2026-04"),
        ("posting_date", date(2026, 3, 18)),
        ("account_code", "1002"),
        ("debit", Decimal("1250.01")),
        ("credit", Decimal("0.01")),
        ("currency", "USD"),
        ("description", "Petty cash replenishmen"),
        ("preparer", "chen.we"),
        ("document_ref", "REQ-8872"),
    ],
)
def test_every_field_affects_the_digest(field, value):
    """No field may be silently excluded from the preimage."""
    assert record_digest(entry(**{field: value}), JOURNAL_ENTRY_V1) != record_digest(
        entry(), JOURNAL_ENTRY_V1
    )


def test_null_differs_from_empty_string():
    assert record_digest(entry(description=None), JOURNAL_ENTRY_V1) != record_digest(
        entry(description=""), JOURNAL_ENTRY_V1
    )


def test_amount_moved_between_sides_changes_digest():
    """1250 debit and 1250 credit are opposite facts, not the same one."""
    assert record_digest(
        entry(debit=Decimal("0.00"), credit=Decimal("1250.00")), JOURNAL_ENTRY_V1
    ) != record_digest(entry(), JOURNAL_ENTRY_V1)


def test_length_prefixing_prevents_boundary_collision():
    """``{"ab": "c"}`` and ``{"a": "bc"}`` must not share a preimage.

    Without length prefixes, concatenating name and value would render both
    as ``abc`` -- a trivially exploitable collision.
    """
    left = RecordSchema(
        "test.collide", 1, (FieldSpec("ab", FieldType.STRING), )
    )
    right = RecordSchema(
        "test.collide", 1, (FieldSpec("a", FieldType.STRING), )
    )
    assert canonical_preimage({"ab": "c"}, left) != canonical_preimage(
        {"a": "bc"}, right
    )


def test_schema_version_is_bound_into_the_digest():
    v1 = RecordSchema("test.rec", 1, (FieldSpec("x", FieldType.STRING),))
    v2 = RecordSchema("test.rec", 2, (FieldSpec("x", FieldType.STRING),))
    assert record_digest({"x": "same"}, v1) != record_digest({"x": "same"}, v2)


def test_schema_id_is_bound_into_the_digest():
    a = RecordSchema("test.a", 1, (FieldSpec("x", FieldType.STRING),))
    b = RecordSchema("test.b", 1, (FieldSpec("x", FieldType.STRING),))
    assert record_digest({"x": "same"}, a) != record_digest({"x": "same"}, b)


# --------------------------------------------------------------------------
# Rejection: ambiguity must fail loudly rather than hash to something
# --------------------------------------------------------------------------


def test_float_money_is_rejected():
    with pytest.raises(TypeError, match="float"):
        record_digest(entry(debit=1250.00), JOURNAL_ENTRY_V1)


def test_excess_precision_is_rejected_not_rounded():
    with pytest.raises(ValueError, match="precision"):
        record_digest(entry(debit=Decimal("1250.005")), JOURNAL_ENTRY_V1)


def test_naive_datetime_is_rejected():
    schema = RecordSchema("test.event", 1, (FieldSpec("at", FieldType.DATETIME),))
    with pytest.raises(ValueError, match="naive"):
        record_digest({"at": datetime(2026, 3, 17, 12, 0, 0)}, schema)


def test_missing_field_is_rejected():
    incomplete = entry()
    del incomplete["currency"]
    with pytest.raises(KeyError, match="currency"):
        record_digest(incomplete, JOURNAL_ENTRY_V1)


def test_undeclared_field_is_rejected():
    """Silently ignoring an extra field would leave it outside the digest."""
    with pytest.raises(ValueError, match="undeclared"):
        record_digest(entry(approved_by="li.hua"), JOURNAL_ENTRY_V1)


def test_non_nullable_field_rejects_none():
    with pytest.raises(ValueError, match="nullable"):
        record_digest(entry(preparer=None), JOURNAL_ENTRY_V1)


def test_digest_is_deterministic_across_calls():
    first = record_digest(entry(), JOURNAL_ENTRY_V1)
    assert all(record_digest(entry(), JOURNAL_ENTRY_V1) == first for _ in range(10))
    assert len(first) == 32
