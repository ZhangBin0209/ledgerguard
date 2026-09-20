"""EVM anchoring backend.

This is the only chain-specific code in the project, and it is the test of
whether the backend abstraction was real: it implements the same three methods
as the simulators and passes ``tests/test_backends.py`` unchanged.  Nothing
above :mod:`ledgerguard.backends` knows which backend it is talking to.

**On-chain, off-chain.**  Only the 32-byte commitment digest is committed.
The commitment body -- root, interval, predecessor digest -- is kept off-chain
and re-hashed against the anchored digest when retrieved, so what the registry
stores per batch is fixed (the digest plus a few words of bookkeeping; see the
contract) no matter how many records the batch covers, and gas per anchoring
transaction is constant.  This is what makes batch size a real
cost/granularity trade-off: large batches anchor cheaply but localise
tampering coarsely, small batches the reverse.

**Provenance of the body.**  Because the chain holds only the digest, this
backend needs somewhere to keep the bodies.  It delegates to any other
:class:`~ledgerguard.backends.ChainBackend` as a body store -- typically a
:class:`~ledgerguard.backends.FileBackend` sitting beside the ledger.  The
store is untrusted: a body that has been edited no longer hashes to the value
the chain holds, and :meth:`fetch` refuses it.

**Testing without a node.**  ``EthereumTesterProvider`` runs a real EVM in
process, so the test suite exercises actual contract execution offline and in
CI.  A deployment against a public or consortium chain differs only in the
Web3 provider passed to :meth:`deploy`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .backends import (
    AnchorError,
    AnchorRecord,
    ChainBackend,
    CorruptAnchorError,
    DuplicateAnchorError,
    MemoryBackend,
)
from .commitment import BatchCommitment

ARTIFACT_PATH = Path(__file__).parent / "artifacts" / "AnchorRegistry.json"


def load_artifact() -> dict[str, Any]:
    """The compiled contract: ABI and deployment bytecode.

    Shipping the artifact means neither users nor reviewers need a Solidity
    toolchain to run the software.  The source is in ``contracts/`` and
    ``scripts/compile_contract.py`` regenerates this file for anyone who wants
    to verify that the bytecode matches.
    """
    return json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))


class MissingDependencyError(AnchorError):
    """web3 is not installed."""


def _require_web3():
    try:
        import web3
    except ImportError as exc:  # pragma: no cover - exercised only without web3
        raise MissingDependencyError(
            "the EVM backend requires web3; install with: pip install "
            "'ledgerguard[evm]'"
        ) from exc
    return web3


class EVMBackend(ChainBackend):
    """Anchors commitment digests in an ``AnchorRegistry`` contract.

    Args:
        w3: A connected ``Web3`` instance.
        address: Address of a deployed ``AnchorRegistry``.
        account: Address to send transactions from.  Defaults to the first
            account the provider exposes.
        body_store: Backend holding the off-chain commitment bodies.  Defaults
            to an in-memory store, which is fine for tests but loses the
            bodies on exit; production deployments should pass a
            :class:`~ledgerguard.backends.FileBackend`.
    """

    name = "evm"

    def __init__(
        self,
        w3: Any,
        address: str,
        account: str | None = None,
        body_store: ChainBackend | None = None,
    ) -> None:
        _require_web3()
        artifact = load_artifact()
        self.w3 = w3
        self.address = w3.to_checksum_address(address)
        self.contract = w3.eth.contract(address=self.address, abi=artifact["abi"])
        self.account = w3.to_checksum_address(account) if account else w3.eth.accounts[0]
        self.body_store = body_store if body_store is not None else MemoryBackend()
        self.last_gas_used: int | None = None

    # -- deployment --------------------------------------------------------

    @classmethod
    def deploy(
        cls,
        w3: Any,
        account: str | None = None,
        body_store: ChainBackend | None = None,
    ) -> EVMBackend:
        """Deploy a fresh registry and return a backend bound to it."""
        _require_web3()
        artifact = load_artifact()
        sender = w3.to_checksum_address(account) if account else w3.eth.accounts[0]
        factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        tx_hash = factory.constructor().transact({"from": sender})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return cls(w3, receipt.contractAddress, sender, body_store)

    @classmethod
    def in_memory_chain(cls, body_store: ChainBackend | None = None) -> EVMBackend:
        """A backend on an in-process EVM, for tests and reproducible runs.

        Requires ``eth-tester``.  The EVM is real; only the network is not.
        """
        _require_web3()
        from web3 import EthereumTesterProvider, Web3

        w3 = Web3(EthereumTesterProvider())
        return cls.deploy(w3, body_store=body_store)

    # -- ChainBackend interface -------------------------------------------

    def anchor(self, commitment: BatchCommitment) -> AnchorRecord:
        batch_id = commitment.batch_id
        digest = commitment.digest()

        if self.contract.functions.isAnchored(batch_id).call():
            raise DuplicateAnchorError(
                f"batch {batch_id!r} is already anchored on chain at {self.address}"
            )

        tx_hash = self.contract.functions.anchor(batch_id, digest).transact(
            {"from": self.account}
        )
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt.status != 1:
            raise AnchorError(f"anchoring transaction for {batch_id!r} reverted")
        self.last_gas_used = receipt.gasUsed

        # The body is stored only after the chain write succeeds, so a failed
        # transaction never leaves a body claiming to be anchored.
        try:
            self.body_store.anchor(commitment)
        except DuplicateAnchorError:
            pass  # the body was already retained; the chain write is what counts

        return AnchorRecord(
            commitment=commitment,
            digest=digest,
            backend=self.name,
            # web3 7 dropped the 0x prefix from HexBytes.hex(). The reference
            # is what an auditor pastes into a block explorer, so normalise it
            # here rather than leaving the caller to guess the convention.
            reference=self.w3.to_hex(tx_hash),
            anchored_at=datetime.fromtimestamp(
                self.w3.eth.get_block(receipt.blockNumber).timestamp, tz=timezone.utc
            ),
        )

    def fetch(self, batch_id: str) -> AnchorRecord | None:
        if not self.contract.functions.isAnchored(batch_id).call():
            return None

        digest, block_number, timestamp, _ = self.contract.functions.get(
            batch_id
        ).call()

        stored = self.body_store.fetch(batch_id)
        if stored is None:
            raise CorruptAnchorError(
                f"batch {batch_id!r} is anchored on chain but its commitment body "
                "is not in the body store; the anchor cannot be interpreted"
            )

        record = AnchorRecord(
            commitment=stored.commitment,
            digest=bytes(digest),
            backend=self.name,
            reference=f"block:{block_number}",
            anchored_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
        )
        # _validate re-hashes the body against the on-chain digest, which is
        # the check that makes an untrusted body store safe to use.
        return self._validate(record)

    def __iter__(self) -> Iterator[AnchorRecord]:
        """Walk the registry in the order batches were anchored.

        Batch ids are stored on chain only as keccak hashes, so the readable
        ids come from the body store; the on-chain ordering is authoritative
        and the body store is matched against it.
        """
        by_key = {
            self.w3.keccak(text=record.batch_id): record
            for record in self.body_store
        }
        for index in range(self.contract.functions.count().call()):
            batch_key, digest, block_number, timestamp = self.contract.functions.at(
                index
            ).call()
            stored = by_key.get(bytes(batch_key))
            if stored is None:
                raise CorruptAnchorError(
                    f"anchor {index} on chain has no commitment body in the "
                    "body store"
                )
            yield self._validate(
                AnchorRecord(
                    commitment=stored.commitment,
                    digest=bytes(digest),
                    backend=self.name,
                    reference=f"block:{block_number}",
                    anchored_at=datetime.fromtimestamp(timestamp, tz=timezone.utc),
                )
            )

    def __len__(self) -> int:
        return self.contract.functions.count().call()

    # -- cost reporting ----------------------------------------------------

    def estimate_gas(self, commitment: BatchCommitment) -> int:
        """Gas an anchoring transaction would consume.

        Reported per batch rather than per record: since the batch size does
        not affect the transaction, this figure divided by the record count is
        the per-record on-chain cost, which is the number worth quoting.
        ``scripts/experiments.py`` records the measured figure in
        ``results/gas.csv``.
        """
        return self.contract.functions.anchor(
            commitment.batch_id, commitment.digest()
        ).estimate_gas({"from": self.account})
