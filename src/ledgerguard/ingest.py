"""Reading records out of the systems that actually hold them.

Ledgers do not live in JSON files.  They live in relational tables, in
warehouse exports, in CSV dumps handed over by a finance team.  This module
reads those and produces the typed dictionaries the rest of the toolkit
expects.

**Coercion is not canonicalisation.**  The two are deliberately separate
stages and the distinction matters.  A database hands back whatever its driver
chose -- SQLite has no date type, so a date arrives as a string; a numeric
column may arrive as ``int``, ``str`` or, disastrously, ``float``.  Coercion
turns those into the Python types the schema declares.  Canonicalisation then
turns typed values into bytes.  Keeping them apart means that supporting a new
data source requires only a coercion path and cannot change a single digest;
if the two were merged, every new adapter would risk silently altering what
records hash to.

**Floats are refused, not converted.**  If a monetary column comes back as a
float, the precision is already lost before this module sees it, and quietly
calling ``Decimal(str(value))`` would launder a real problem into a
plausible-looking number.  The fix belongs in the query -- cast to text or to
an integer minor-unit column -- so the error says that.
"""

from __future__ import annotations

import csv
import re
import sqlite3
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .schema import FieldSpec, FieldType, RecordSchema

#: Strings accepted as booleans, case-insensitively.
_TRUE = frozenset({"1", "true", "t", "yes", "y"})
_FALSE = frozenset({"0", "false", "f", "no", "n"})

#: Strings treated as SQL NULL when a column arrives as text.
#:
#: This applies to every field type, including STRING, and the trade-off is
#: deliberate: CSV has no NULL, so ``""`` (and the ``\N`` / ``NULL`` markers
#: exporters write) is the only way a CSV export can carry a null, and a
#: record must hash the same whether it arrived from CSV or from a database
#: that returned a real NULL.  The cost is that a nullable STRING field whose
#: legitimate value is literally ``"None"`` or ``"null"`` is read as null.  A
#: source in which those are real values should map the column through a
#: CAST or a ``columns=`` alias to a non-nullable field, where the marker is
#: refused instead.  Non-nullable fields are never affected: a marker there
#: is an error.
_NULLISH = frozenset({"", "null", "none", "\\n"})

_SQL_IDENTIFIER = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

#: SQLite's internal tables. They are valid identifiers and reading one would
#: never yield a record, so the failure would surface as a confusing coercion
#: error about a missing column rather than as the mistake it is.
_RESERVED_TABLES = frozenset({"sqlite_master", "sqlite_schema",
                              "sqlite_temp_master", "sqlite_temp_schema",
                              "sqlite_sequence", "sqlite_stat1"})


class IngestError(ValueError):
    """A source value could not be coerced to its declared field type."""


def _fail(spec: FieldSpec, value: Any, reason: str) -> IngestError:
    return IngestError(
        f"field {spec.name!r}: cannot read {value!r} as {spec.type.name} -- {reason}"
    )


def _check_table(table: str) -> None:
    """Reject anything that is not a plain, non-internal table name.

    Table names cannot be bound as parameters, so the identifier is restricted
    rather than escaped: anything outside the allowed shape is refused instead
    of being interpolated.
    """
    if not _SQL_IDENTIFIER.match(table):
        raise ValueError(f"{table!r} is not a plain SQL identifier")
    if table.lower() in _RESERVED_TABLES:
        raise ValueError(f"{table!r} is a SQLite internal table, not a ledger")


def _select_ordered(table: str, schema: RecordSchema) -> str:
    """A SELECT ordering by the sequence field, numerically.

    The cast is not decorative. SQLite applies type affinity per value, so a
    sequence column that was created as TEXT -- which is what a naive export
    or an ORM without an explicit type will produce -- sorts lexicographically:
    1, 10, 100, 2. The commitment layer requires ascending numeric order, and
    a batch built from a lexicographic read would commit to an interval whose
    first and last sequence numbers are simply wrong.
    """
    order = schema.sequence_field
    query = f'SELECT * FROM "{table}"'
    if order:
        query += f' ORDER BY CAST("{order}" AS INTEGER)'
    return query


def coerce_value(value: Any, spec: FieldSpec) -> Any:
    """Convert one source value to the Python type its field declares.

    Raises:
        IngestError: the value cannot be represented as the declared type.
    """
    if value is None or (
        isinstance(value, str) and value.strip().lower() in _NULLISH
    ):
        if not spec.nullable:
            raise _fail(spec, value, "the field is not nullable")
        return None

    if spec.type is FieldType.STRING:
        return value if isinstance(value, str) else str(value)

    if spec.type is FieldType.INTEGER:
        if isinstance(value, bool):
            raise _fail(spec, value, "a boolean is not an integer here")
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            raise _fail(spec, value, "cast the column to text or integer in the query")
        try:
            return int(str(value).strip())
        except ValueError:
            raise _fail(spec, value, "not an integer") from None

    if spec.type is FieldType.MONEY:
        if isinstance(value, float):
            raise _fail(
                spec,
                value,
                "a float has already lost decimal precision; select the column "
                "as text, or store minor units as an integer",
            )
        if isinstance(value, Decimal):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            return Decimal(value)
        try:
            return Decimal(str(value).strip())
        except InvalidOperation:
            raise _fail(spec, value, "not a decimal number") from None

    if spec.type is FieldType.DATE:
        if isinstance(value, datetime):
            raise _fail(spec, value, "a datetime cannot be narrowed to a date silently")
        if isinstance(value, date):
            return value
        text = str(value).strip()
        try:
            return date.fromisoformat(text)
        except ValueError:
            pass
        # A DATE column that SQLite or an ORM rendered as "YYYY-MM-DD 00:00:00"
        # is still a date, so a *naive* timestamp string is accepted and
        # narrowed. The whole string must parse: an earlier version kept the
        # first ten characters, which accepted "2026-03-17junk" and silently
        # discarded whatever followed. A timestamp carrying an offset is
        # refused, because which calendar date it falls on depends on the
        # zone, and guessing is what this module exists not to do.
        try:
            parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
        except ValueError:
            raise _fail(spec, value, "not an ISO 8601 date") from None
        if parsed.tzinfo is not None:
            raise _fail(
                spec, value,
                "a zoned timestamp is not narrowed to a date silently; cast it "
                "in the query or declare the field DATETIME",
            )
        return parsed.date()

    if spec.type is FieldType.DATETIME:
        if isinstance(value, datetime):
            parsed = value
        else:
            text = str(value).strip().replace(" ", "T", 1)
            # SQLite and several exporters render UTC with a trailing Z, which
            # fromisoformat rejected before Python 3.11.
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                raise _fail(spec, value, "not an ISO 8601 timestamp") from None
        if parsed.tzinfo is None:
            # A naive timestamp from a database is almost always UTC, but
            # "almost always" is not a basis for a digest, so the caller must
            # say so explicitly via read_* (assume_utc).
            raise _fail(
                spec,
                value,
                "no timezone; pass assume_utc=True if the source stores UTC",
            )
        return parsed

    if spec.type is FieldType.BOOLEAN:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            if value in (0, 1):
                return bool(value)
            raise _fail(spec, value, "only 0 and 1 are unambiguous")
        text = str(value).strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
        raise _fail(spec, value, "not a recognised boolean")

    raise _fail(spec, value, "unsupported field type")  # pragma: no cover


def coerce_record(
    row: Mapping[str, Any],
    schema: RecordSchema,
    columns: Mapping[str, str] | None = None,
    assume_utc: bool = False,
) -> dict[str, Any]:
    """Convert one source row into a schema-conforming record.

    Args:
        row: The source row, keyed by column name.
        schema: Target schema.
        columns: Optional mapping of schema field name to source column name,
            for sources whose column names differ from the schema's.
        assume_utc: Treat naive timestamps as UTC.  Off by default: a naive
            timestamp is ambiguous, and guessing would make the digest depend
            on the reader's assumption rather than on the data.

    Raises:
        IngestError: a column is missing or a value cannot be coerced.
    """
    columns = columns or {}
    record: dict[str, Any] = {}

    for spec in schema.fields:
        source = columns.get(spec.name, spec.name)
        if source not in row:
            raise IngestError(
                f"source row has no column {source!r} for field {spec.name!r}"
            )
        value = row[source]
        if (
            assume_utc
            and spec.type is FieldType.DATETIME
            and isinstance(value, datetime)
            and value.tzinfo is None
        ):
            value = value.replace(tzinfo=timezone.utc)
        elif (
            assume_utc
            and spec.type is FieldType.DATETIME
            and isinstance(value, str)
            and value.strip()
            and not re.search(r"(Z|[+-]\d{2}:?\d{2})\Z", value.strip())
        ):
            value = value.strip() + "+00:00"
        record[spec.name] = coerce_value(value, spec)

    return record


def read_rows(
    rows: Iterable[Mapping[str, Any]],
    schema: RecordSchema,
    columns: Mapping[str, str] | None = None,
    assume_utc: bool = False,
) -> list[dict[str, Any]]:
    """Coerce an iterable of source rows, reporting the row number on failure."""
    out = []
    for number, row in enumerate(rows, start=1):
        try:
            out.append(coerce_record(row, schema, columns, assume_utc))
        except IngestError as exc:
            raise IngestError(f"row {number}: {exc}") from None
    return out


def read_csv(
    path: str | Path,
    schema: RecordSchema,
    columns: Mapping[str, str] | None = None,
    assume_utc: bool = False,
    encoding: str = "utf-8-sig",
) -> list[dict[str, Any]]:
    """Read records from a CSV export.

    ``utf-8-sig`` is the default encoding because exports from spreadsheet
    software routinely carry a byte-order mark, which would otherwise become
    part of the first column's name and make every lookup fail.
    """
    with Path(path).open("r", newline="", encoding=encoding) as handle:
        return read_rows(csv.DictReader(handle), schema, columns, assume_utc)


def read_sqlite(
    database: str | Path | sqlite3.Connection,
    schema: RecordSchema,
    table: str | None = None,
    query: str | None = None,
    parameters: Sequence[Any] = (),
    columns: Mapping[str, str] | None = None,
    assume_utc: bool = False,
) -> list[dict[str, Any]]:
    """Read records from a SQLite database.

    Exactly one of ``table`` or ``query`` must be given.  When ``table`` is
    used the rows come back ordered by the schema's sequence field, since the
    commitment layer requires ascending order and a bare ``SELECT`` guarantees
    none.

    Args:
        database: Path to a database file, or an open connection.
        schema: Target schema.
        table: Table to read in full.
        query: Arbitrary SQL, for reading a subset or joining across tables.
        parameters: Bound parameters for ``query``.
        columns: Schema field to source column mapping.
        assume_utc: Treat naive timestamps as UTC.  SQLite has no timestamp
            type, so this is usually needed.

    Raises:
        ValueError: neither or both of ``table`` and ``query`` were given, or
            ``table`` is not a plain identifier.
    """
    if (table is None) == (query is None):
        raise ValueError("pass exactly one of table or query")

    if table is not None:
        _check_table(table)
        query = _select_ordered(table, schema)

    assert query is not None  # guaranteed by the exclusivity check above

    if isinstance(database, sqlite3.Connection):
        connection, owns_connection = database, False
    else:
        connection, owns_connection = sqlite3.connect(str(database)), True

    try:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(query, tuple(parameters))
        rows = [dict(row) for row in cursor.fetchall()]
    finally:
        if owns_connection:
            connection.close()

    return read_rows(rows, schema, columns, assume_utc)


def iter_sqlite(
    connection: sqlite3.Connection,
    schema: RecordSchema,
    table: str | None = None,
    query: str | None = None,
    parameters: Sequence[Any] = (),
    columns: Mapping[str, str] | None = None,
    assume_utc: bool = False,
    batch_size: int = 1000,
) -> Iterator[list[dict[str, Any]]]:
    """Stream a SQLite table in batches, for ledgers too large to hold at once.

    Yields lists of coerced records, each already in the order the commitment
    layer needs, so a caller can anchor a large ledger without materialising
    it.
    """
    if (table is None) == (query is None):
        raise ValueError("pass exactly one of table or query")

    if table is not None:
        _check_table(table)
        query = _select_ordered(table, schema)

    assert query is not None  # guaranteed by the exclusivity check above
    connection.row_factory = sqlite3.Row
    cursor = connection.execute(query, tuple(parameters))
    offset = 0
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        try:
            yield read_rows(
                [dict(r) for r in rows], schema, columns, assume_utc
            )
        except IngestError as exc:
            raise IngestError(f"batch starting at row {offset + 1}: {exc}") from None
        offset += len(rows)


def write_sqlite(
    connection: sqlite3.Connection,
    records: Sequence[Mapping[str, Any]],
    schema: RecordSchema,
    table: str = "records",
) -> None:
    """Write records to a SQLite table, for fixtures and round-trip testing.

    Values are stored the way a real system would store them -- amounts and
    timestamps as text, booleans as integers -- so that a round trip through
    this function exercises the coercion path rather than bypassing it.
    """
    _check_table(table)

    # Integer and boolean columns are declared INTEGER so the fixture matches
    # how a real system would store them; everything else is TEXT, which is
    # how amounts and timestamps reach a database that has no type for them.
    def column_type(spec: FieldSpec) -> str:
        return (
            "INTEGER"
            if spec.type in (FieldType.INTEGER, FieldType.BOOLEAN)
            else "TEXT"
        )

    column_sql = ", ".join(
        f'"{f.name}" {column_type(f)}' for f in schema.fields
    )
    connection.execute(f'DROP TABLE IF EXISTS "{table}"')
    connection.execute(f'CREATE TABLE "{table}" ({column_sql})')

    placeholders = ", ".join("?" for _ in schema.fields)
    names = ", ".join(f'"{f.name}"' for f in schema.fields)
    rows: list[list[Any]] = []
    for record in records:
        row: list[Any] = []
        for spec in schema.fields:
            value = record[spec.name]
            if value is None:
                row.append(None)
            elif spec.type is FieldType.BOOLEAN:
                row.append(1 if value else 0)
            elif spec.type is FieldType.INTEGER:
                row.append(int(value))
            elif isinstance(value, (date, datetime)):
                row.append(value.isoformat())
            else:
                row.append(str(value))
        rows.append(row)

    connection.executemany(
        f'INSERT INTO "{table}" ({names}) VALUES ({placeholders})', rows
    )
    connection.commit()
