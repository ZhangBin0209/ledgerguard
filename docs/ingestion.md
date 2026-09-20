# Ingestion

## Coercion is not canonicalisation

Two separate stages, deliberately. Coercion turns whatever a source hands back
— SQLite has no date type, a numeric column may arrive as `int`, `str` or
`float` — into the Python types the schema declares. Canonicalisation then
turns typed values into bytes.

Keeping them apart means supporting a new data source needs only a coercion
path and cannot change a single digest. Merged, every new adapter would risk
silently altering what records hash to.

## CSV

```python
from ledgerguard.ingest import read_csv
from ledgerguard.profiles import get_profile

records = read_csv("export.csv", get_profile("accounting"))
```

The default encoding is `utf-8-sig` because spreadsheet exports routinely
carry a byte-order mark, which would otherwise become part of the first
column's name.

## SQLite

```python
from ledgerguard.ingest import read_sqlite

records = read_sqlite("erp.db", schema, table="gl_journal")

records = read_sqlite(
    "erp.db", schema,
    query="SELECT * FROM gl_journal WHERE period = ? ORDER BY line_seq",
    parameters=("2026-03",),
)
```

Reads by table are ordered with `ORDER BY CAST(seq AS INTEGER)`. The cast is
not decorative: SQLite applies type affinity per value, so a sequence column
created as `TEXT` sorts 1, 10, 100, 2. A batch built from a lexicographic read
would commit to an interval whose bounds are simply wrong.

For ledgers too large to hold in memory, `iter_sqlite` yields ordered batches.

## Column mapping

When source column names differ from the schema's:

```python
records = read_csv("export.csv", schema, columns={
    "line_seq": "ID", "voucher_no": "DOC_NO", "debit": "DR_AMT",
})
```

## Timezones

A naive timestamp is refused by default. Guessing would make the digest depend
on the reader's assumption rather than on the data. When the source is known
to store UTC — which SQLite usually is — say so:

```python
records = read_sqlite("runs.db", schema, table="events", assume_utc=True)
```

## Floats

A monetary column arriving as a float is refused, not converted. The precision
is already lost before ingestion sees it, and `Decimal(str(value))` would
launder a real problem into a plausible-looking number. Fix it in the query:
select the column as text, or store minor units as an integer.

## Null markers

A value of `""`, `NULL`, `none` or `\N` (case-insensitively) is read as SQL
NULL for a *nullable* field of any type, and refused for a non-nullable one.
This is what lets a record hash identically whether it arrived from CSV,
which has no NULL, or from a database that returned one. The cost is that a
nullable STRING whose legitimate value is literally `"None"` reads as null;
if a source has such values, alias the column onto a non-nullable field with
`columns=`, where the marker is an error instead of a null.

## Dates

A DATE field accepts a bare ISO date and a *naive* timestamp rendered by a
DATE column (`2026-03-17 00:00:00`), which is narrowed to its date. The whole
string must parse: trailing text is refused rather than dropped, and a
timestamp carrying a timezone offset is refused, because which calendar date
it falls on depends on the zone. Declare the field DATETIME, or cast in the
query, if the column really holds instants.
