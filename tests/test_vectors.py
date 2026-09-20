"""Frozen test vectors.

Every other test in this suite is *relative*: it checks that the same input
gives the same digest, or that a different input gives a different one. All of
them would pass if the canonical encoding were replaced wholesale — the
digests would all change together and nothing would notice.

That is precisely the failure this file exists to catch. A digest is a
promise: a ledger anchored last year must still verify against the code
running today. Changing the encoding silently breaks every anchor in
existence, and the breakage would only surface as an inexplicable mass
verification failure in someone's production ledger, long after the commit
that caused it.

**If a test here fails, the fix is almost never to update the file.** It is
either to revert the change, or — if the encoding genuinely must change — to
bump the schema version, which puts old and new records in disjoint digest
spaces and leaves existing anchors verifiable under their own version.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from ledgerguard import (
    BatchBuilder,
    MerkleTree,
    canonical_preimage,
    record_digest,
    synth,
)
from ledgerguard.merkle import leaf_hash, node_hash
from ledgerguard.profiles import get_profile
from ledgerguard.schema import FieldSpec, FieldType, RecordSchema

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())

ACCOUNTING = get_profile("accounting")
PROVENANCE = get_profile("provenance")

#: Exercises every field type, including combinations the shipped profiles
#: use sparsely: a negative amount, microsecond precision, a null.
ALL_TYPES = RecordSchema(
    "vectors.all_types", 1, sequence_field="seq",
    fields=(
        FieldSpec("seq", FieldType.INTEGER),
        FieldSpec("text", FieldType.STRING),
        FieldSpec("money", FieldType.MONEY, scale=2),
        FieldSpec("when", FieldType.DATE),
        FieldSpec("at", FieldType.DATETIME),
        FieldSpec("flag", FieldType.BOOLEAN),
        FieldSpec("maybe", FieldType.STRING, nullable=True),
    ),
)

ACCOUNTING_RECORD = {
    "line_seq": 1041, "voucher_no": "JV-2026-000412", "line_no": 1,
    "period": "2026-03", "posting_date": date(2026, 3, 17),
    "account_code": "1001", "debit": Decimal("1250.00"),
    "credit": Decimal("0.00"), "currency": "CNY",
    "description": "Petty cash replenishment", "preparer": "chen.wei",
    "document_ref": "REQ-8871",
}

PROVENANCE_RECORD = {
    "event_seq": 7, "run_id": "RUN-2026-00001", "event_type": "measurement",
    "recorded_at": datetime(2026, 2, 3, 9, 15, 30, tzinfo=timezone.utc),
    "instrument_id": "LC-MS-01", "operator": "m.torres", "sample_id": "S-40277",
    "artifact_digest": None, "parameters": "scans=32", "is_automated": False,
}

ALL_TYPES_RECORD = {
    "seq": 1, "text": "café ☕", "money": Decimal("-12.34"),
    "when": date(2026, 1, 2),
    "at": datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc),
    "flag": True, "maybe": None,
}


# -- record digests ---------------------------------------------------------

@pytest.mark.parametrize("key,record,schema", [
    ("accounting.journal_entry@1", ACCOUNTING_RECORD, ACCOUNTING),
    ("provenance.instrument_event@1", PROVENANCE_RECORD, PROVENANCE),
    ("vectors.all_types@1", ALL_TYPES_RECORD, ALL_TYPES),
])
def test_record_digest_matches_the_frozen_vector(key, record, schema):
    assert record_digest(record, schema).hex() == VECTORS["record_digests"][key]


@pytest.mark.parametrize("key,record,schema", [
    ("accounting.journal_entry@1", ACCOUNTING_RECORD, ACCOUNTING),
    ("vectors.all_types@1", ALL_TYPES_RECORD, ALL_TYPES),
])
def test_canonical_preimage_matches_the_frozen_vector(key, record, schema):
    """Pins the bytes, not just the hash.

    Two encodings could in principle differ while agreeing on a hash for one
    record; freezing the preimage catches a wire-format change directly.
    """
    actual = hashlib.sha256(canonical_preimage(record, schema)).hexdigest()
    assert actual == VECTORS["canonical_preimages_sha256"][key]


# -- Merkle construction ----------------------------------------------------

def test_empty_root_matches():
    assert MerkleTree().root.hex() == VECTORS["merkle"]["empty_root"]


def test_domain_separation_prefixes_match():
    """Pins the 0x00 / 0x01 prefixes that block the second-preimage attack."""
    assert leaf_hash(b"\x00" * 32).hex() == VECTORS["merkle"]["leaf_hash_of_zero_digest"]
    assert node_hash(b"\x00" * 32, b"\x11" * 32).hex() == \
        VECTORS["merkle"]["node_hash_of_two_zero_digests"]


@pytest.mark.parametrize("size", ["1", "2", "3", "5", "8", "13", "100"])
def test_tree_shape_matches_at_each_size(size):
    """Odd sizes are where the RFC 6962 split rule differs from Bitcoin's."""
    n = int(size)
    tree = MerkleTree(hashlib.sha256(f"leaf-{i}".encode()).digest() for i in range(n))
    assert tree.root.hex() == VECTORS["merkle"]["roots_by_size"][size]


# -- commitments ------------------------------------------------------------

def _reference_batch():
    builder = BatchBuilder(ACCOUNTING, VECTORS["commitment"]["batch_id"])
    builder.extend(synth.generate(vouchers=25, seed=99).records[:16])
    return builder.seal()


def test_commitment_digest_matches():
    """Pins what actually reaches the chain, including its field order."""
    batch = _reference_batch()
    expected = VECTORS["commitment"]
    assert batch.commitment.root.hex() == expected["root"]
    assert batch.commitment.tree_size == expected["tree_size"]
    interval = batch.commitment.interval
    assert [interval.first_seq, interval.last_seq, interval.count] == expected["interval"]
    assert batch.commitment.digest().hex() == expected["digest"]


def test_inclusion_proof_matches():
    proof = _reference_batch().tree.prove(5)
    expected = VECTORS["inclusion_proof_index_5"]
    assert proof.digest.hex() == expected["leaf_digest"]
    assert [h.hex() for h in proof.path] == expected["path"]


# -- generators -------------------------------------------------------------

@pytest.mark.parametrize("key,records,schema", [
    ("accounting_seed99_25vouchers", None, ACCOUNTING),
    ("provenance_seed99_12runs", None, PROVENANCE),
])
def test_synthetic_ledgers_are_stable_across_versions(key, records, schema):
    """A generator change would silently invalidate every published result.

    Reported detection rates and timings are tied to specific seeds; if the
    same seed stops producing the same ledger, nothing in the paper can be
    reproduced.
    """
    ledger = (synth.generate(vouchers=25, seed=99) if "accounting" in key
              else synth.generate_provenance(runs=12, seed=99))
    expected = VECTORS["synthetic_ledgers"][key]
    assert len(ledger.records) == expected["count"]
    combined = hashlib.sha256(
        b"".join(record_digest(r, schema) for r in ledger.records)).hexdigest()
    assert combined == expected["digest_of_digests"]


def test_vectors_file_declares_its_format_version():
    assert VECTORS["format_version"] == 1


def test_non_genesis_commitment_digest_matches():
    """Pins the encoding of the predecessor.

    The genesis vector above cannot: replacing ``self.prev_digest`` with
    ``GENESIS_DIGEST`` produces identical bytes for a first batch, so the
    mutation passed unnoticed until this vector was added.
    """
    from ledgerguard import BatchBuilder

    expected = VECTORS["commitment_non_genesis"]
    builder = BatchBuilder(
        ACCOUNTING, expected["batch_id"], bytes.fromhex(expected["prev_digest"]))
    builder.extend(synth.generate(vouchers=25, seed=99).records[:16])
    commitment = builder.seal().commitment

    assert commitment.root.hex() == expected["root"]
    assert commitment.digest().hex() == expected["digest"]
    # And it must differ from the genesis-predecessor batch with the same rows.
    assert commitment.digest().hex() != VECTORS["commitment"]["digest"]
