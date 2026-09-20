"""Generic record schema.

A schema describes the fields of an append-only structured record and the
rules under which those fields are canonicalised.  Nothing in this module is
specific to accounting; the accounting journal-entry schema is one profile
built on top of it (see ``ledgerguard.profiles.accounting``).

Every schema carries an identifier and a version.  Both are folded into the
record digest, so a record can never be mistaken for a record of a different
shape, and a change to the canonicalisation rules is always visible as a
change in the digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class FieldType(Enum):
    """Canonical field types.

    The integer value is the type tag written into the canonical encoding.
    These values are part of the wire format: never renumber them, and add
    new types only with a schema-version bump.
    """

    NULL = 0x00
    STRING = 0x01
    INTEGER = 0x02
    MONEY = 0x03
    DATE = 0x04
    DATETIME = 0x05
    BOOLEAN = 0x06


@dataclass(frozen=True)
class FieldSpec:
    """Declaration of a single field.

    Args:
        name: Field name.  Encoded into the digest, so renaming a field
            changes every digest under the schema.
        type: Canonical type.
        nullable: Whether ``None`` is an accepted value.
        scale: For ``MONEY`` only, the number of decimal places.  Values are
            converted to integer minor units at this scale, which is what
            makes digests stable across systems that render the same amount
            as ``100``, ``100.0`` or ``100.00``.
        strip: For ``STRING`` only, whether surrounding whitespace is removed
            before hashing.  Defaults to ``True`` because trailing whitespace
            is the single most common spurious difference between exports of
            the same record from different systems.
    """

    name: str
    type: FieldType
    nullable: bool = False
    scale: int | None = None
    strip: bool = True

    def __post_init__(self) -> None:
        if self.type is FieldType.MONEY:
            if self.scale is None or self.scale < 0:
                raise ValueError(
                    f"field {self.name!r}: MONEY requires a non-negative scale"
                )
        elif self.scale is not None:
            raise ValueError(
                f"field {self.name!r}: scale is only meaningful for MONEY"
            )
        if self.type is FieldType.NULL:
            raise ValueError(
                f"field {self.name!r}: NULL is a value tag, not a field type"
            )


@dataclass(frozen=True)
class RecordSchema:
    """An ordered, versioned set of field declarations.

    Args:
        schema_id: Stable identifier, e.g. ``"accounting.journal_entry"``.
        version: Schema version.  Bump on any change to fields or rules.
        fields: Field declarations.  Declaration order is irrelevant to the
            digest -- fields are always canonicalised in sorted name order --
            but it is preserved for display and export.
        sequence_field: Name of the field carrying the monotonically
            increasing record number, if the schema has one.  Interval
            commitments (which is how deletion is detected) require it.
    """

    schema_id: str
    version: int
    fields: tuple[FieldSpec, ...]
    sequence_field: str | None = None
    _by_name: Mapping[str, FieldSpec] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.schema_id:
            raise ValueError("schema_id must be non-empty")
        if self.version < 1:
            raise ValueError("version must be >= 1")
        if not self.fields:
            raise ValueError("schema must declare at least one field")

        names = [f.name for f in self.fields]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate field names: {sorted(duplicates)}")

        if self.sequence_field is not None:
            if self.sequence_field not in names:
                raise ValueError(
                    f"sequence_field {self.sequence_field!r} is not a declared field"
                )
            spec = next(f for f in self.fields if f.name == self.sequence_field)
            if spec.type is not FieldType.INTEGER:
                raise ValueError("sequence_field must be an INTEGER field")
            if spec.nullable:
                raise ValueError("sequence_field must not be nullable")

        object.__setattr__(self, "_by_name", {f.name: f for f in self.fields})

    @property
    def field_names(self) -> tuple[str, ...]:
        """Field names in declaration order."""
        return tuple(f.name for f in self.fields)

    @property
    def canonical_order(self) -> tuple[FieldSpec, ...]:
        """Field specs in the order used for hashing (sorted by name)."""
        return tuple(sorted(self.fields, key=lambda f: f.name))

    def spec(self, name: str) -> FieldSpec:
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"{self.schema_id}: no such field {name!r}") from None
