"""Read a ledger out of SQLite, anchor it, then detect a direct database edit.

This is the motivating scenario: someone with write access changes a row, and
the application's own audit log cannot be trusted to record it because the same
credentials govern both.
"""

import sqlite3
import tempfile
from pathlib import Path

from ledgerguard import BatchBuilder, MemoryBackend, Verifier, format_report, synth
from ledgerguard.ingest import read_sqlite, write_sqlite
from ledgerguard.profiles import get_profile

SCHEMA = get_profile("accounting")
database = Path(tempfile.mkdtemp()) / "erp.db"

# Stand in for the ERP.
connection = sqlite3.connect(database)
write_sqlite(connection, synth.generate(vouchers=80, seed=2).records,
             SCHEMA, "gl_journal")
connection.close()

# Read it the way an operator would, and anchor what is there today.
records = read_sqlite(database, SCHEMA, table="gl_journal")
backend, witnesses = MemoryBackend(), {}
for index in range(0, len(records), 50):
    builder = BatchBuilder(SCHEMA, f"B{index // 50}", backend.next_prev_digest())
    builder.extend(records[index:index + 50])
    batch = builder.seal()
    backend.anchor(batch.commitment)
    witnesses[batch.commitment.batch_id] = batch.witness()
print(f"anchored {len(records)} records straight from {database.name}\n")

# A privileged user edits the table directly.
connection = sqlite3.connect(database)
connection.execute("UPDATE gl_journal SET debit = '1.00' WHERE line_seq = 31")
connection.execute("DELETE FROM gl_journal WHERE line_seq = 64")
connection.commit()
connection.close()
print("UPDATE line_seq=31, DELETE line_seq=64\n")

report = Verifier(backend, SCHEMA).verify_ledger(
    read_sqlite(database, SCHEMA, table="gl_journal"), witnesses)
print(format_report(report))
