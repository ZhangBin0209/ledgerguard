"""End-to-end demonstration.

Anchors three batches of journal entries to a simulated chain, then replays
four kinds of tampering against the anchors. Everything runs offline.
"""
from datetime import date
from decimal import Decimal

from ledgerguard import (
    BatchBuilder,
    MemoryBackend,
    check_interval,
    record_digest,
    verify_chain,
)
from ledgerguard.merkle import InclusionProof
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1, validate_voucher_balance

SCHEMA = JOURNAL_ENTRY_V1


def ln(seq, voucher, no, debit="0.00", credit="0.00", desc=None):
    return {"line_seq": seq, "voucher_no": voucher, "line_no": no,
            "period": "2026-03", "posting_date": date(2026, 3, 17),
            "account_code": "1001", "debit": Decimal(debit),
            "credit": Decimal(credit), "currency": "CNY", "description": desc,
            "preparer": "chen.wei", "document_ref": None}


BATCHES = {
    "2026-03-17T09": [
        ln(1041, "JV-2026-000412", 1, debit="1250.00", desc="Petty cash"),
        ln(1042, "JV-2026-000412", 2, credit="1250.00"),
        ln(1043, "JV-2026-000413", 1, debit="8800.00", desc="Supplier payment"),
        ln(1044, "JV-2026-000413", 2, credit="8800.00"),
    ],
    "2026-03-17T10": [
        ln(1045, "JV-2026-000414", 1, debit="430.50", desc="Travel"),
        ln(1046, "JV-2026-000414", 2, credit="430.50"),
        # 1047-1048 burned by a voided voucher: the batch is legitimately sparse
        ln(1049, "JV-2026-000416", 1, debit="15000.00", desc="Equipment"),
        ln(1050, "JV-2026-000416", 2, credit="15000.00"),
    ],
    "2026-03-17T11": [
        ln(1051, "JV-2026-000417", 1, debit="620.00", desc="Utilities"),
        ln(1052, "JV-2026-000417", 2, credit="620.00"),
    ],
}

chain = MemoryBackend()
sealed = {}

print("=" * 66)
print("ANCHORING")
print("=" * 66)
for batch_id, records in BATCHES.items():
    validate_voucher_balance(records)
    builder = BatchBuilder(SCHEMA, batch_id, chain.next_prev_digest())
    builder.extend(records)
    batch = builder.seal()
    sealed[batch_id] = batch
    receipt = chain.anchor(batch.commitment)
    iv = batch.commitment.interval
    print(f"  {batch_id}  n={iv.count:2d}  seq {iv.first_seq}-{iv.last_seq}"
          f"{'' if iv.is_dense else f' ({iv.gap_count} gaps)'}"
          f"  digest {receipt.digest.hex()[:16]}...")
print(f"\n  on-chain footprint: {len(chain)} x 32 bytes for "
      f"{sum(len(b) for b in BATCHES.values())} records")
verify_chain(chain.chain())
print("  chain verified")

print()
print("=" * 66)
print("TAMPERING")
print("=" * 66)

# --- 1. amount altered in place -------------------------------------------
batch = sealed["2026-03-17T09"]
anchor = chain.fetch("2026-03-17T09")
altered = dict(batch.records[2])
altered["debit"] = Decimal("8000.00")
proof = batch.prove_sequence(1043)
replay = InclusionProof(proof.index, proof.tree_size,
                        record_digest(altered, SCHEMA), proof.path)
print("\n[1] amount changed 8800.00 -> 8000.00 on voucher JV-2026-000413")
print(f"    original proof against anchored root : "
      f"{'ok' if proof.verify(anchor.commitment.root) else 'fail'}")
print(f"    altered  proof against anchored root : "
      f"{'ok' if replay.verify(anchor.commitment.root) else 'MISMATCH -> MODIFIED'}")

# --- 2. record deleted from a dense batch ---------------------------------
survivors = [r for r in batch.records if r["line_seq"] != 1043]
f = check_interval(anchor.commitment, survivors, SCHEMA)
print("\n[2] the whole line deleted from the database instead")
print(f"    committed {f.committed_count} records, found {f.observed_count}")
print(f"    verdict: DELETED, sequence {f.missing_sequences[0]}")

# --- 3. record deleted from a sparse batch --------------------------------
sparse = sealed["2026-03-17T10"]
anchor2 = chain.fetch("2026-03-17T10")
survivors2 = [r for r in sparse.records if r["line_seq"] != 1049]
f2 = check_interval(anchor2.commitment, survivors2, SCHEMA)
print("\n[3] a line deleted from a batch that already had legitimate gaps")
print(f"    committed {f2.committed_count} records, found {f2.observed_count}")
print("    verdict: DELETED (count short; gaps make the sequence unnameable)")

# --- 4. an entire batch removed -------------------------------------------
print("\n[4] the middle batch removed from the anchor store entirely")
partial = [c for c in chain.chain() if c.batch_id != "2026-03-17T10"]
try:
    verify_chain(partial)
    print("    verdict: undetected")
except ValueError as exc:
    print("    each surviving batch still verifies on its own, but:")
    print(f"    verdict: {str(exc)[:70]}")

print()
