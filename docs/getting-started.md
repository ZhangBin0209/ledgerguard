# Getting started

```bash
pip install -e ".[dev]"
pytest
```

## Five minutes

```bash
# 1. A synthetic ledger, reproducible from its seed
ledgerguard generate --vouchers 500 --seed 1 -o ledger.json

# 2. Batch it, commit it, anchor it
ledgerguard anchor ledger.json --batch-size 100

# 3. Check it
ledgerguard verify ledger.json        # exit 0
```

`anchor` writes two files. `anchors.jsonl` holds the commitments; it is a
**simulator** — an append-only file under the same control as the ledger —
adequate for experiments and teaching, not for the threat the tool exists
for. `witnesses.json` holds the per-record digests; they are what let
verification name the record that changed rather than only report that the
batch differs. Losing the witnesses costs precision, not soundness.

For the real thing, anchor the same batches to a contract:

```bash
pip install 'ledgerguard[evm]'
ledgerguard deploy --rpc http://localhost:8545          # prints the registry address
ledgerguard anchor ledger.json --backend evm --rpc http://localhost:8545 --contract 0x…
ledgerguard verify ledger.json --backend evm --rpc http://localhost:8545 --contract 0x…
```

The commitment bodies go to `bodies.jsonl` (`--body-store`); only the 32-byte
digest of each goes on chain, and the body is re-hashed against it on every
read. See [Anchoring on chain](chain.md).

## Seeing a detection

```bash
python - <<'PY'
from pathlib import Path
from ledgerguard import tamper
from ledgerguard.cli import read_ledger, write_ledger
records = read_ledger(Path("ledger.json"))
result = tamper.inject(records, seed=1, amount=1, deletion=1)
write_ledger(Path("tampered.json"), result.records)
print(result.log.counts())
PY

ledgerguard verify tampered.json      # exit 1, names both records
```

The exit code is part of the interface: `verify` returns 1 on any discrepancy
and 2 when it cannot verify at all — a missing or empty anchor store, an
unreadable one, every anchor under a different profile — so it can run as a
scheduled job or a CI step without a silent pass. Verification only reads
the anchor store; a torn final line left by an interrupted `anchor` is
reported and read around, and repaired by the next `anchor`.

## From a real database

```bash
ledgerguard ingest erp.db --table gl_journal -o ledger.json
ledgerguard anchor ledger.json
# ... time passes, someone edits the table ...
ledgerguard ingest erp.db --table gl_journal -o now.json
ledgerguard verify now.json
```

See [Ingestion](ingestion.md) for column mapping and timezone handling.

## In Docker

```bash
docker build -t ledgerguard .
docker run --rm ledgerguard          # tests
docker run --rm ledgerguard demo     # narrated walkthrough
```
