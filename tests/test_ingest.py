"""Ingestion tests.

The property under test throughout: a record read from CSV or SQLite must
produce the same digest as the record that was written there. If coercion
changed anything, integrity checking across a real export would be impossible.
"""

from __future__ import annotations

import csv
import sqlite3
from datetime import date, datetime, timezone
from decimal import Decimal

import pytest

from ledgerguard import record_digest, synth
from ledgerguard.ingest import (
    IngestError,
    coerce_record,
    coerce_value,
    iter_sqlite,
    read_csv,
    read_rows,
    read_sqlite,
    write_sqlite,
)
from ledgerguard.profiles import get_profile
from ledgerguard.schema import FieldSpec, FieldType

ACCOUNTING = get_profile("accounting")
PROVENANCE = get_profile("provenance")


# -- value coercion ---------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("1250.00", Decimal("1250.00")), ("1250", Decimal("1250")),
    (1250, Decimal(1250)), (Decimal("1.5"), Decimal("1.5")),
])
def test_money_from_text_and_int(raw, expected):
    spec = FieldSpec("debit", FieldType.MONEY, scale=2)
    assert coerce_value(raw, spec) == expected


def test_money_from_float_is_refused_with_a_usable_message():
    """The precision is already gone; laundering it would hide a real bug."""
    spec = FieldSpec("debit", FieldType.MONEY, scale=2)
    with pytest.raises(IngestError, match="select the column as text"):
        coerce_value(1250.10, spec)


def test_integer_from_float_is_refused():
    spec = FieldSpec("n", FieldType.INTEGER)
    with pytest.raises(IngestError, match="cast the column"):
        coerce_value(3.0, spec)


@pytest.mark.parametrize("raw", ["2026-03-17", "2026-03-17 09:30:00", date(2026, 3, 17)])
def test_date_from_several_source_renderings(raw):
    assert coerce_value(raw, FieldSpec("d", FieldType.DATE)) == date(2026, 3, 17)


def test_datetime_accepts_the_z_suffix():
    spec = FieldSpec("t", FieldType.DATETIME)
    assert coerce_value("2026-03-17T09:30:00Z", spec) == \
           datetime(2026, 3, 17, 9, 30, tzinfo=timezone.utc)


def test_datetime_accepts_a_space_separator():
    """SQLite's CURRENT_TIMESTAMP renders this way."""
    spec = FieldSpec("t", FieldType.DATETIME)
    assert coerce_value("2026-03-17 09:30:00+00:00", spec).hour == 9


def test_naive_datetime_is_refused_by_default():
    """Guessing a timezone would make the digest depend on the reader."""
    spec = FieldSpec("t", FieldType.DATETIME)
    with pytest.raises(IngestError, match="assume_utc"):
        coerce_value("2026-03-17T09:30:00", spec)


@pytest.mark.parametrize("raw,expected", [
    ("1", True), ("true", True), ("YES", True), (1, True),
    ("0", False), ("false", False), ("n", False), (0, False),
])
def test_boolean_spellings(raw, expected):
    assert coerce_value(raw, FieldSpec("b", FieldType.BOOLEAN)) is expected


def test_ambiguous_boolean_is_refused():
    with pytest.raises(IngestError, match="unambiguous"):
        coerce_value(2, FieldSpec("b", FieldType.BOOLEAN))


@pytest.mark.parametrize("raw", ["", "NULL", "none", None])
def test_nullish_values_become_none(raw):
    spec = FieldSpec("d", FieldType.STRING, nullable=True)
    assert coerce_value(raw, spec) is None


def test_null_in_a_non_nullable_field_is_refused():
    with pytest.raises(IngestError, match="not nullable"):
        coerce_value("", FieldSpec("s", FieldType.STRING))


# -- record coercion --------------------------------------------------------

def test_missing_column_names_the_field():
    with pytest.raises(IngestError, match="no column 'voucher_no'"):
        coerce_record({"line_seq": "1"}, ACCOUNTING)


def test_row_number_is_reported_on_failure():
    ledger = synth.generate(vouchers=5, seed=1)
    rows = [{k: str(v) for k, v in r.items()} for r in ledger.records]
    rows[2]["debit"] = "not-a-number"
    with pytest.raises(IngestError, match="row 3"):
        read_rows(rows, ACCOUNTING)


def test_column_mapping_handles_foreign_names():
    ledger = synth.generate(vouchers=2, seed=2)
    original = ledger.records[0]
    renamed = {f"src_{k}": v for k, v in original.items()}
    mapping = {name: f"src_{name}" for name in ACCOUNTING.field_names}

    restored = coerce_record(renamed, ACCOUNTING, columns=mapping)
    assert record_digest(restored, ACCOUNTING) == record_digest(original, ACCOUNTING)


# -- CSV --------------------------------------------------------------------

def test_csv_round_trip_preserves_digests(tmp_path):
    ledger = synth.generate(vouchers=40, seed=3)
    path = tmp_path / "ledger.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(ACCOUNTING.field_names))
        writer.writeheader()
        for record in ledger.records:
            writer.writerow({k: ("" if v is None else v) for k, v in record.items()})

    restored = read_csv(path, ACCOUNTING)
    assert [record_digest(r, ACCOUNTING) for r in restored] == \
           [record_digest(r, ACCOUNTING) for r in ledger.records]


def test_csv_byte_order_mark_is_tolerated(tmp_path):
    """Spreadsheet exports routinely carry one; it would corrupt the first
    column name and make every lookup fail."""
    path = tmp_path / "bom.csv"
    header = ",".join(ACCOUNTING.field_names)
    ledger = synth.generate(vouchers=1, seed=4)
    row = ",".join(
        "" if ledger.records[0][f] is None else str(ledger.records[0][f])
        for f in ACCOUNTING.field_names
    )
    path.write_bytes(("\ufeff" + header + "\n" + row + "\n").encode("utf-8"))

    restored = read_csv(path, ACCOUNTING)
    assert record_digest(restored[0], ACCOUNTING) == \
           record_digest(ledger.records[0], ACCOUNTING)


# -- SQLite -----------------------------------------------------------------

@pytest.fixture
def accounting_db(tmp_path):
    ledger = synth.generate(vouchers=60, seed=5)
    connection = sqlite3.connect(tmp_path / "ledger.db")
    write_sqlite(connection, ledger.records, ACCOUNTING, "journal")
    connection.close()
    return tmp_path / "ledger.db", ledger


def test_sqlite_round_trip_preserves_digests(accounting_db):
    path, ledger = accounting_db
    restored = read_sqlite(path, ACCOUNTING, table="journal")
    assert [record_digest(r, ACCOUNTING) for r in restored] == \
           [record_digest(r, ACCOUNTING) for r in ledger.records]


def test_sqlite_reads_are_ordered_by_sequence(accounting_db):
    """A bare SELECT guarantees no order; the commitment layer requires one."""
    path, _ = accounting_db
    restored = read_sqlite(path, ACCOUNTING, table="journal")
    seqs = [r["line_seq"] for r in restored]
    assert seqs == sorted(seqs)


def test_sqlite_accepts_a_custom_query(accounting_db):
    path, ledger = accounting_db
    restored = read_sqlite(
        path, ACCOUNTING,
        query='SELECT * FROM journal WHERE currency = ? ORDER BY line_seq',
        parameters=("CNY",),
    )
    assert restored and all(r["currency"] == "CNY" for r in restored)
    assert len(restored) < len(ledger)


def test_sqlite_rejects_both_table_and_query(accounting_db):
    path, _ = accounting_db
    with pytest.raises(ValueError, match="exactly one"):
        read_sqlite(path, ACCOUNTING, table="journal", query="SELECT 1")


def test_sqlite_rejects_a_non_identifier_table_name(accounting_db):
    """Table names cannot be bound, so they are restricted rather than escaped."""
    path, _ = accounting_db
    with pytest.raises(ValueError, match="plain SQL identifier"):
        read_sqlite(path, ACCOUNTING, table="journal; DROP TABLE journal")


def test_sqlite_accepts_an_open_connection(accounting_db):
    path, ledger = accounting_db
    connection = sqlite3.connect(path)
    try:
        restored = read_sqlite(connection, ACCOUNTING, table="journal")
        assert len(restored) == len(ledger)
        connection.execute("SELECT 1")  # still open
    finally:
        connection.close()


def test_streaming_yields_the_same_records(accounting_db):
    path, ledger = accounting_db
    connection = sqlite3.connect(path)
    try:
        streamed = [r for batch in iter_sqlite(connection, ACCOUNTING,
                                               table="journal", batch_size=25)
                    for r in batch]
    finally:
        connection.close()
    assert [record_digest(r, ACCOUNTING) for r in streamed] == \
           [record_digest(r, ACCOUNTING) for r in ledger.records]


# -- the second profile goes through the same path -------------------------

def test_provenance_survives_sqlite_with_assume_utc(tmp_path):
    """SQLite has no timestamp type, so this is the realistic case."""
    ledger = synth.generate_provenance(runs=20, seed=6)
    connection = sqlite3.connect(tmp_path / "runs.db")
    write_sqlite(connection, ledger.records, PROVENANCE, "events")
    restored = read_sqlite(connection, PROVENANCE, table="events")
    connection.close()

    assert [record_digest(r, PROVENANCE) for r in restored] == \
           [record_digest(r, PROVENANCE) for r in ledger.records]


def test_provenance_csv_round_trip(tmp_path):
    ledger = synth.generate_provenance(runs=15, seed=7)
    path = tmp_path / "events.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(PROVENANCE.field_names))
        writer.writeheader()
        for record in ledger.records:
            writer.writerow({
                k: ("" if v is None else (v.isoformat()
                    if isinstance(v, datetime) else v))
                for k, v in record.items()
            })

    restored = read_csv(path, PROVENANCE)
    assert [record_digest(r, PROVENANCE) for r in restored] == \
           [record_digest(r, PROVENANCE) for r in ledger.records]


def test_ingested_ledger_anchors_and_verifies(accounting_db):
    """The point of ingestion: a real export goes straight into the pipeline."""
    from ledgerguard import BatchBuilder, MemoryBackend, Verifier

    path, _ = accounting_db
    records = read_sqlite(path, ACCOUNTING, table="journal")

    backend = MemoryBackend()
    witnesses = {}
    for i in range(0, len(records), 50):
        chunk = records[i:i + 50]
        builder = BatchBuilder(ACCOUNTING, f"B{i//50}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()

    report = Verifier(backend, ACCOUNTING).verify_ledger(records, witnesses)
    assert report.intact


def test_text_sequence_column_still_reads_in_numeric_order(tmp_path):
    """Regression: a TEXT sequence column sorts 1, 10, 100, 2 without a cast.

    A batch built from a lexicographic read would commit to an interval whose
    first and last sequence numbers are wrong, and the error would surface
    much later as an unexplained verification failure.
    """
    ledger = synth.generate(vouchers=60, seed=8)
    connection = sqlite3.connect(tmp_path / "text.db")
    columns = ", ".join(f'"{f}" TEXT' for f in ACCOUNTING.field_names)
    connection.execute(f"CREATE TABLE journal ({columns})")
    placeholders = ", ".join("?" for _ in ACCOUNTING.field_names)
    connection.executemany(
        f"INSERT INTO journal VALUES ({placeholders})",
        [[None if r[f] is None else str(r[f]) for f in ACCOUNTING.field_names]
         for r in ledger.records],
    )
    connection.commit()

    # The hazard, demonstrated.
    raw = [row[0] for row in connection.execute(
        'SELECT "line_seq" FROM journal ORDER BY "line_seq"')]
    assert raw != sorted(raw, key=int)

    restored = read_sqlite(connection, ACCOUNTING, table="journal")
    connection.close()

    seqs = [r["line_seq"] for r in restored]
    assert seqs == sorted(seqs)
    assert [record_digest(r, ACCOUNTING) for r in restored] == \
           [record_digest(r, ACCOUNTING) for r in ledger.records]


@pytest.mark.parametrize("table", [
    "sqlite_master", "SQLITE_MASTER", "sqlite_schema", "sqlite_sequence",
])
def test_sqlite_internal_tables_are_refused(table):
    """A valid identifier, but never a ledger.

    Reading one would fail later with a coercion error about a missing column,
    which says nothing about the actual mistake.
    """
    with pytest.raises(ValueError, match="internal table"):
        read_sqlite(":memory:", ACCOUNTING, table=table)


@pytest.mark.parametrize("table", [
    't; DROP TABLE t', 't"; --', '"t"', "t UNION SELECT 1", "t t", "",
])
def test_non_identifier_table_names_are_refused(table):
    with pytest.raises(ValueError, match="plain SQL identifier"):
        read_sqlite(":memory:", ACCOUNTING, table=table)


# -- 0.6.8 ------------------------------------------------------------------


@pytest.mark.parametrize("raw, reason", [
    ("2026-03-17T23:59:59+05:00", "zoned"),   # which date depends on the zone
    ("2026-03-17junk", "not an ISO"),
    ("2026-03-17 25:00:00", "not an ISO"),
])
def test_date_strings_are_not_silently_truncated(raw, reason):
    """Regression: the first ten characters used to be kept, so trailing junk
    and a timezone offset were discarded without a word."""
    spec = FieldSpec("posting_date", FieldType.DATE)
    with pytest.raises(IngestError, match=reason):
        coerce_value(raw, spec)


@pytest.mark.parametrize("raw", ["2026-03-17", "2026-03-17 00:00:00",
                                 "2026-03-17T09:30:00"])
def test_naive_date_renderings_still_coerce(raw):
    spec = FieldSpec("posting_date", FieldType.DATE)
    assert coerce_value(raw, spec) == date(2026, 3, 17)
