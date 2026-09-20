# Profiles

A profile supplies a `RecordSchema` and the domain rules that make a finding
interpretable in that domain's language. The layers below — canonicalisation,
Merkle, commitments, backends, verification — import nothing from `profiles/`.

## Shipped profiles

**`accounting`** (`accounting.journal_entry` v1). One line of a journal entry.
Rules: each line carries an amount on exactly one side; vouchers balance per
currency. Sequence field `line_seq`, kept separate from `voucher_no` because
voucher numbers are not dense — voided documents leave gaps — and so cannot
carry the deletion argument.

**`provenance`** (`provenance.instrument_event` v1). One event in an
instrument run. Rules: events within a run are chronologically ordered
consistently with their sequence; measurements follow a calibration; artefact
digests are well-formed. Sequence field `event_seq`.

The two share no field name. That they work through the same pipeline is what
the second profile exists to demonstrate.

## Writing a profile

```python
from ledgerguard.schema import FieldSpec, FieldType, RecordSchema

SHIPMENT_EVENT_V1 = RecordSchema(
    schema_id="logistics.shipment_event",
    version=1,
    sequence_field="event_seq",
    fields=(
        FieldSpec("event_seq", FieldType.INTEGER),
        FieldSpec("consignment_id", FieldType.STRING),
        FieldSpec("occurred_at", FieldType.DATETIME),
        FieldSpec("location", FieldType.STRING),
        FieldSpec("custodian", FieldType.STRING),
        FieldSpec("sealed", FieldType.BOOLEAN),
        FieldSpec("notes", FieldType.STRING, nullable=True),
    ),
)
```

Then register it in `profiles/__init__.py` and write validators for the
invariants a generic integrity check would miss — the analogue of "debits
equal credits".

Requirements: a `sequence_field` that is a non-nullable integer, and a
`schema_id`/`version` pair that is stable. Both are folded into every digest,
so changing a field list without bumping the version invalidates existing
anchors silently.

If adding a profile requires editing anything outside `profiles/`, that is a
leak in the abstraction.
