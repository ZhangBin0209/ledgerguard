"""EVM backend tests.

The shared backend contract is covered in test_backends.py, which the EVM
backend passes unchanged. This file covers what is specific to running on a
chain: gas behaviour, on-chain reverts, and the untrusted body store.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

pytest.importorskip("web3", reason="the EVM backend requires web3")
pytest.importorskip("eth_tester", reason="in-process EVM requires eth-tester")

from eth_tester.exceptions import TransactionFailed

from ledgerguard import (
    BatchBuilder,
    CorruptAnchorError,
    FileBackend,
    synth,
    verify_chain,
)
from ledgerguard.evm import EVMBackend, load_artifact
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1

SCHEMA = JOURNAL_ENTRY_V1


def ln(seq):
    return {
        "line_seq": seq, "voucher_no": f"JV-{seq}", "line_no": 1,
        "period": "2026-03", "posting_date": date(2026, 3, 17),
        "account_code": "1001", "debit": Decimal("100.00"),
        "credit": Decimal("0.00"), "currency": "CNY", "description": None,
        "preparer": "chen.wei", "document_ref": None,
    }


def build(seqs, batch_id="B1", prev=None):
    from ledgerguard import GENESIS_DIGEST
    b = BatchBuilder(SCHEMA, batch_id, prev or GENESIS_DIGEST)
    b.extend(ln(s) for s in seqs)
    return b.seal()


@pytest.fixture
def chain(tmp_path):
    return EVMBackend.in_memory_chain(
        body_store=FileBackend(tmp_path / "bodies.jsonl"))


# -- artifact ---------------------------------------------------------------

def test_artifact_is_loadable():
    artifact = load_artifact()
    assert artifact["contractName"] == "AnchorRegistry"
    assert artifact["bytecode"].startswith("0x")
    names = {e["name"] for e in artifact["abi"] if e.get("type") == "function"}
    assert names == {"anchor", "get", "isAnchored", "count", "at"}


# -- gas --------------------------------------------------------------------

def test_gas_is_independent_of_batch_size(chain):
    """The core economic claim: cost scales with batch count, not ledger size.

    Only the 32-byte digest reaches the chain, so a batch of 10 000 records
    costs the same to anchor as a batch of 10.
    """
    small = build(range(1, 11), "small")
    large = build(range(100, 10_100), "large")
    assert len(large) == 10_000

    gas_small = chain.estimate_gas(small.commitment)
    gas_large = chain.estimate_gas(large.commitment)
    assert gas_small == gas_large


def test_per_record_cost_falls_with_batch_size(chain):
    a = build(range(1, 11), "a")
    chain.anchor(a.commitment)
    per_record_small = chain.last_gas_used / len(a)

    b = build(range(1000, 2000), "b", chain.next_prev_digest())
    chain.anchor(b.commitment)
    per_record_large = chain.last_gas_used / len(b)

    assert per_record_large < per_record_small / 50


# -- on-chain enforcement ---------------------------------------------------

def test_contract_refuses_a_second_anchor_for_the_same_batch(chain):
    """Append-only is enforced by the contract, not only by the client."""
    batch = build([1, 2, 3], "B1")
    chain.anchor(batch.commitment)
    original = chain.contract.functions.get("B1").call()[0]

    # Bypass the client-side check and call the contract directly.
    with pytest.raises(TransactionFailed):
        chain.contract.functions.anchor(
            "B1", b"\x11" * 32).transact({"from": chain.account})

    # The revert must leave the original digest in place, not merely fail.
    assert chain.contract.functions.get("B1").call()[0] == original


def test_contract_rejects_a_zero_digest(chain):
    """A zero digest is an uninitialised variable, and would make isAnchored
    ambiguous against the mapping's default value."""
    with pytest.raises(TransactionFailed):
        chain.contract.functions.anchor(
            "Z", b"\x00" * 32).transact({"from": chain.account})
    assert not chain.contract.functions.isAnchored("Z").call()


def test_contract_rejects_an_empty_batch_id(chain):
    with pytest.raises(TransactionFailed):
        chain.contract.functions.anchor(
            "", b"\x11" * 32).transact({"from": chain.account})
    assert chain.contract.functions.count().call() == 0


def test_anchor_records_a_block_timestamp(chain):
    record = chain.anchor(build([1, 2, 3]).commitment)
    assert record.anchored_at.tzinfo is not None
    assert record.reference.startswith("0x")


# -- the body store is untrusted --------------------------------------------

def test_edited_body_is_rejected_against_the_on_chain_digest(tmp_path):
    """An operator who rewrites the off-chain body cannot rewrite the chain."""
    import json

    bodies = tmp_path / "bodies.jsonl"
    chain = EVMBackend.in_memory_chain(body_store=FileBackend(bodies))
    chain.anchor(build([1, 2, 3], "B1").commitment)

    entry = json.loads(bodies.read_text().strip())
    entry["commitment"]["count"] = 2
    entry["commitment"]["tree_size"] = 2
    entry["commitment"]["last_seq"] = 2
    bodies.write_text(json.dumps(entry) + "\n")

    reopened = EVMBackend(chain.w3, chain.address, chain.account,
                          FileBackend(bodies))
    with pytest.raises(CorruptAnchorError, match="anchored"):
        reopened.fetch("B1")


def test_missing_body_is_reported_not_silently_ignored(chain, tmp_path):
    """An anchor whose body is lost is unusable, and must say so."""
    chain.anchor(build([1, 2, 3], "B1").commitment)

    orphaned = EVMBackend(chain.w3, chain.address, chain.account,
                          FileBackend(tmp_path / "empty.jsonl"))
    with pytest.raises(CorruptAnchorError, match="body"):
        orphaned.fetch("B1")


# -- ordering and chain verification ----------------------------------------

def test_iteration_follows_on_chain_order(chain):
    for i in range(4):
        chain.anchor(build([i * 100 + j for j in range(3)], f"B{i}",
                           chain.next_prev_digest()).commitment)
    assert [r.batch_id for r in chain] == ["B0", "B1", "B2", "B3"]


def test_full_ledger_anchors_and_verifies(chain):
    ledger = synth.generate(vouchers=40, seed=2, batch_size=30)
    for i, chunk in enumerate(ledger.batches()):
        b = BatchBuilder(SCHEMA, f"B{i:03d}", chain.next_prev_digest())
        b.extend(chunk)
        chain.anchor(b.seal().commitment)

    verify_chain(chain.chain())
    assert len(chain) == len(ledger.batches())


def test_verifier_works_against_the_evm_backend(chain):
    """The verifier is backend-agnostic; nothing above backends.py changes."""
    from ledgerguard import Verdict, Verifier, tamper

    ledger = synth.generate(vouchers=40, seed=3, batch_size=30)
    witnesses = {}
    for i, chunk in enumerate(ledger.batches()):
        b = BatchBuilder(SCHEMA, f"B{i:03d}", chain.next_prev_digest())
        b.extend(chunk)
        batch = b.seal()
        chain.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()

    result = tamper.inject(ledger.records, seed=4, amount=2, deletion=1)
    report = Verifier(chain, SCHEMA).verify_ledger(result.records, witnesses)

    assert not report.intact
    assert report.count(Verdict.MODIFIED) == 2
    assert report.count(Verdict.DELETED) == 1
