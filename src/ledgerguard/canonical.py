"""Canonical encoding and digest computation.

The problem this module solves: the same logical record exported from two
different systems is rarely byte-identical.  Field order differs, an amount
appears as ``100``, ``100.0`` or ``"100.00"``, a date arrives as a string in
one export and a ``date`` object in another, a null is ``None`` here and
``""`` there, and text may be in a different Unicode normalisation form.  A
digest taken over the raw export is therefore useless for integrity checking
across system boundaries.

The canonical encoding fixes every one of those degrees of freedom:

1.  Fields are encoded in sorted name order, so declaration and export order
    are irrelevant.
2.  Every element is length-prefixed, so no two distinct records can produce
    the same byte string by concatenation.  Without this, the fields
    ``{"a": "bc"}`` and ``{"ab": "c"}`` could collide.
3.  Monetary amounts are converted to integer minor units at the scale
    declared in the schema.  Excess precision is an error, never silently
    rounded.
4.  Dates are ISO 8601; datetimes are normalised to UTC and rendered with a
    trailing ``Z``, so an offset-shifted duplicate of the same instant hashes
    identically.
5.  Nulls carry their own type tag and are therefore distinguishable from an
    empty string.
6.  Text is NFC-normalised and encoded as UTF-8, optionally stripped.
7.  The schema id and version are folded into the preimage, so records of
    different shapes live in disjoint digest spaces.

The output of :func:`canonical_preimage` is the exact byte string that gets
hashed.  It is exposed deliberately: an auditor who disputes a digest must be
able to inspect what was hashed, not merely re-run the hash function.
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from ._encoding import lp, u32
from .schema import FieldSpec, FieldType, RecordSchema

# Domain separation tag.  Prefixing the preimage prevents a canonical record
# encoding from ever being reinterpreted as a Merkle node preimage.
_RECORD_TAG = b"\x00lg-record-v1"

def _encode_string(value: Any, spec: FieldSpec) -> bytes:
    if not isinstance(value, str):
        raise TypeError(
            f"field {spec.name!r}: expected str, got {type(value).__name__}"
        )
    text = unicodedata.normalize("NFC", value)
    if spec.strip:
        text = text.strip()
    return text.encode("utf-8")


def _encode_integer(value: Any, spec: FieldSpec) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"field {spec.name!r}: expected int, got {type(value).__name__}"
        )
    return str(value).encode("ascii")


def _encode_money(value: Any, spec: FieldSpec) -> bytes:
    """Convert to integer minor units at the declared scale.

    ``float`` is rejected outright.  Binary floating point cannot represent
    most decimal fractions exactly, so accepting it would make digests depend
    on how a value happened to round-trip through a float -- exactly the
    class of instability this module exists to eliminate.
    """
    if isinstance(value, float):
        raise TypeError(
            f"field {spec.name!r}: float is not accepted for MONEY; "
            "pass Decimal, int or str to avoid binary rounding"
        )
    if isinstance(value, Decimal):
        amount = value
    elif isinstance(value, int) and not isinstance(value, bool):
        amount = Decimal(value)
    elif isinstance(value, str):
        try:
            amount = Decimal(value.strip())
        except InvalidOperation:
            raise ValueError(
                f"field {spec.name!r}: {value!r} is not a valid decimal"
            ) from None
    else:
        raise TypeError(
            f"field {spec.name!r}: expected Decimal, int or str, "
            f"got {type(value).__name__}"
        )

    if not amount.is_finite():
        raise ValueError(f"field {spec.name!r}: amount must be finite")

    assert spec.scale is not None  # guaranteed by FieldSpec validation
    scaled = amount.scaleb(spec.scale)
    minor = scaled.to_integral_value()
    if scaled != minor:
        raise ValueError(
            f"field {spec.name!r}: {amount} has more precision than the "
            f"declared scale of {spec.scale}"
        )
    return str(int(minor)).encode("ascii")


def _encode_date(value: Any, spec: FieldSpec) -> bytes:
    if isinstance(value, datetime):
        raise TypeError(
            f"field {spec.name!r}: expected date, got datetime; "
            "declare the field as DATETIME or pass value.date()"
        )
    if isinstance(value, date):
        return value.isoformat().encode("ascii")
    if isinstance(value, str):
        return date.fromisoformat(value.strip()).isoformat().encode("ascii")
    raise TypeError(
        f"field {spec.name!r}: expected date or ISO string, "
        f"got {type(value).__name__}"
    )


def _encode_datetime(value: Any, spec: FieldSpec) -> bytes:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.strip())
    if not isinstance(value, datetime):
        raise TypeError(
            f"field {spec.name!r}: expected datetime or ISO string, "
            f"got {type(value).__name__}"
        )
    if value.tzinfo is None:
        raise ValueError(
            f"field {spec.name!r}: naive datetime is ambiguous; attach a timezone"
        )
    utc = value.astimezone(timezone.utc).replace(tzinfo=None)
    # Fixed six-digit microseconds: an instant must not hash differently
    # because one exporter omitted trailing zeros.
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f").encode("ascii") + b"Z"


def _encode_boolean(value: Any, spec: FieldSpec) -> bytes:
    if not isinstance(value, bool):
        raise TypeError(
            f"field {spec.name!r}: expected bool, got {type(value).__name__}"
        )
    return b"1" if value else b"0"


_ENCODERS = {
    FieldType.STRING: _encode_string,
    FieldType.INTEGER: _encode_integer,
    FieldType.MONEY: _encode_money,
    FieldType.DATE: _encode_date,
    FieldType.DATETIME: _encode_datetime,
    FieldType.BOOLEAN: _encode_boolean,
}


def encode_field(value: Any, spec: FieldSpec) -> bytes:
    """Encode one field as ``tag || len(name) || name || len(value) || value``."""
    name_bytes = spec.name.encode("utf-8")

    if value is None:
        if not spec.nullable:
            raise ValueError(f"field {spec.name!r} is not nullable")
        return (
            bytes([FieldType.NULL.value]) + lp(name_bytes) + lp(b"")
        )

    encoded = _ENCODERS[spec.type](value, spec)
    return bytes([spec.type.value]) + lp(name_bytes) + lp(encoded)


def canonical_preimage(record: Mapping[str, Any], schema: RecordSchema) -> bytes:
    """Return the exact bytes that :func:`record_digest` hashes.

    Raises:
        KeyError: a declared field is missing from ``record``.
        ValueError: ``record`` carries fields the schema does not declare, or
            a value violates its field's rules.
        TypeError: a value has the wrong Python type for its field.
    """
    undeclared = set(record) - set(schema.field_names)
    if undeclared:
        raise ValueError(
            f"{schema.schema_id}: undeclared fields {sorted(undeclared)}"
        )

    parts = [
        _RECORD_TAG,
        lp(schema.schema_id.encode("utf-8")),
        lp(str(schema.version).encode("ascii")),
        u32(len(schema.fields)),
    ]
    for spec in schema.canonical_order:
        if spec.name not in record:
            raise KeyError(f"{schema.schema_id}: missing field {spec.name!r}")
        parts.append(encode_field(record[spec.name], spec))
    return b"".join(parts)


def record_digest(record: Mapping[str, Any], schema: RecordSchema) -> bytes:
    """SHA-256 over the canonical preimage.  32 bytes."""
    return hashlib.sha256(canonical_preimage(record, schema)).digest()


def record_digest_hex(record: Mapping[str, Any], schema: RecordSchema) -> str:
    """Hex form of :func:`record_digest`, for reports and logs."""
    return record_digest(record, schema).hex()
