"""Anchor a ledger and detect a modification. The shortest useful example."""

from ledgerguard import BatchBuilder, MemoryBackend, Verifier, format_report, synth
from ledgerguard.profiles import get_profile

SCHEMA = get_profile("accounting")

ledger = synth.generate(vouchers=50, seed=1)
backend = MemoryBackend()
witnesses = {}

for index, chunk in enumerate(ledger.batches()):
    builder = BatchBuilder(SCHEMA, f"B{index}", backend.next_prev_digest())
    builder.extend(chunk)
    batch = builder.seal()
    backend.anchor(batch.commitment)
    witnesses[batch.commitment.batch_id] = batch.witness()

print(f"anchored {len(ledger)} records in {len(witnesses)} batches\n")

# Someone edits a record after the fact.
from decimal import Decimal  # noqa: E402  (imported here to keep the narrative order)

edited = [dict(r) for r in ledger.records]
edited[17]["debit"] = Decimal("1.00")

report = Verifier(backend, SCHEMA).verify_ledger(edited, witnesses)
print(format_report(report))
