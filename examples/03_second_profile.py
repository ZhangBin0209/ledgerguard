"""The same pipeline on instrument-run provenance, with no core changes.

Nothing below `profiles/` is touched. The commitment layer needs a schema with
a sequence field; what the records mean is the profile's business.
"""

from ledgerguard import BatchBuilder, MemoryBackend, Verifier, format_report, synth
from ledgerguard.profiles import get_profile
from ledgerguard.profiles.provenance import (
    CALIBRATION,
    ProvenanceError,
    validate_calibration_order,
)

SCHEMA = get_profile("provenance")

ledger = synth.generate_provenance(runs=40, seed=1)
backend, witnesses = MemoryBackend(), {}
for index, chunk in enumerate(ledger.batches()):
    builder = BatchBuilder(SCHEMA, f"B{index}", backend.next_prev_digest())
    builder.extend(chunk)
    batch = builder.seal()
    backend.anchor(batch.commitment)
    witnesses[batch.commitment.batch_id] = batch.witness()
print(f"anchored {len(ledger)} instrument events\n")

# Remove a calibration record: the run now reports measurements that rest on
# no calibration, and the interval commitment sees the removal.
victim = next(r for r in ledger.records if r["event_type"] == CALIBRATION)
survivors = [r for r in ledger.records if r is not victim]

print(format_report(Verifier(backend, SCHEMA).verify_ledger(survivors, witnesses)))
print()
try:
    validate_calibration_order(survivors)
except ProvenanceError as exc:
    print(f"domain rule also violated: {exc}")
