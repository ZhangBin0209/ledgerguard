# Anchoring on chain

```bash
pip install 'ledgerguard[evm]'
```

## The contract

`contracts/AnchorRegistry.sol` records one 32-byte commitment digest per
batch and offers no update or delete path — not even to a deployer, since an
owner-only override is still an override.

What the registry *stores* per batch is fixed but larger than the digest: the
digest, block number, timestamp and submitter (three storage words) plus the
key in the insertion-order index (one more). None of it depends on how many
records the batch covers, so gas per anchoring transaction is constant —
measured at about 119.6k on `paris` (`results/gas.csv`), with the first anchor
on a fresh registry paying about 17k more to take the counter slot from zero.
The "32 bytes per batch" quoted elsewhere is the committed digest, not the
storage footprint; gas is the honest cost figure.

The compiled artifact is committed, so no Solidity toolchain is needed to run
the software. To verify it matches the source:

```bash
python scripts/compile_contract.py --check
```

## Who can write

Anyone. The contract has no owner and no access control, which is a deliberate
consequence of refusing an update path: an owner role that can do nothing is
indistinguishable from no owner, and one that can do anything reintroduces the
override the design excludes.

The intended deployment is therefore **one registry per organisation** — the
address of the deployed contract is part of the verification context, exactly
as the choice of anchor file is for the file backend. On a shared or public
deployment, batch identifiers are first-come-first-served: a third party who
anchors under your batch id first (by racing your transaction, for instance)
does not forge anything — they cannot produce your commitment digest — but
they do occupy the id, and your anchor is refused as a duplicate. Deploying
your own registry costs one transaction and removes the concern entirely.

## From the command line

```bash
ledgerguard deploy --rpc http://localhost:8545            # prints the address
ledgerguard anchor ledger.json --backend evm --rpc http://localhost:8545 --contract 0x…
ledgerguard verify ledger.json --backend evm --rpc http://localhost:8545 --contract 0x…
```

`--body-store` (default `bodies.jsonl`) is where the commitment bodies live;
`--account` selects the sending address. The default `--backend file` is the
simulator and never touches a chain.

## From Python

```python
from web3 import Web3
from ledgerguard.backends import FileBackend
from ledgerguard.evm import EVMBackend

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
chain = EVMBackend.deploy(w3, body_store=FileBackend("bodies.jsonl"))
chain.anchor(batch.commitment)
```

Everything above `backends.py` is unchanged — the verifier does not know which
backend it is talking to.

## The body store

Only the digest goes on chain; the commitment body lives in the body store.
The store is untrusted: a body that has been edited no longer hashes to the
value the chain holds, and `fetch` refuses it.

## Testing without a node

```python
chain = EVMBackend.in_memory_chain()
```

Runs a real EVM in process via `eth-tester`. The EVM is real; only the network
is not. This is how the test suite exercises contract execution offline.

## Cost

Gas per anchoring transaction is independent of batch size (`results/gas.csv`:
119,596–119,608 across batches of 10 to 5,000 records; the 12-gas spread is
calldata pricing of zero bytes in the digest), so the per-record cost is that
figure divided by the batch size. Large batches anchor cheaply but localise
tampering coarsely when no witness is held; see
`results/fig2_batch_tradeoff.png`.

## What the chain does not do

- Records altered *before* they were anchored are not detected; anchoring
  frequency is a security parameter.
- The verifier trusts its view of the chain. Verifying through a single
  untrusted RPC endpoint trusts that endpoint; use a node you run, a light
  client, or cross-check several.
- If a commitment body is lost, its batch cannot be interpreted and `fetch`
  raises `CorruptAnchorError`: verification fails closed rather than
  degrading. (Losing a *witness* degrades; losing a *body* does not.)
- A digest over a low-entropy record can be inverted by enumeration. Salted
  digests, so that a public registry discloses nothing about record content,
  are planned but not shipped.
