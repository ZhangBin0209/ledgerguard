# LedgerGuard User Manual

**Version 0.6.13** · Tamper evidence and audit verification for append-only structured records

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Functional Modules](#4-functional-modules)
5. [Command-Line Reference](#5-command-line-reference)
6. [Python API Reference](#6-python-api-reference)
7. [Operation Guide](#7-operation-guide)
8. [Profiles and Data Requirements](#8-profiles-and-data-requirements)
9. [Verification, Validation, and Reproducibility](#9-verification-validation-and-reproducibility)
10. [Troubleshooting](#10-troubleshooting)
11. [Support and Version Information](#11-support-and-version-information)
12. [Appendix](#12-appendix)

---

## 1. Introduction

### 1.1 Overview

LedgerGuard is an open-source Python toolkit for producing and verifying tamper evidence for append-only structured records. It is designed for situations in which an auditor, researcher, or data custodian must later determine whether records have been modified, deleted, inserted, or removed as a whole batch after they were committed.

A conventional application audit log can be altered by the same privileged actor who can alter the underlying database. LedgerGuard therefore separates the evidence from the records themselves. Records are canonicalised, hashed, grouped into RFC 6962-style Merkle trees, bound into batch commitments, and anchored through a pluggable backend. Verification later compares the observed records with the anchored commitments.

The default file backend is intentionally a simulator for development, teaching, and reproducible experiments. For an independent anchor, LedgerGuard also ships an EVM backend and an `AnchorRegistry` smart contract that records one 32-byte commitment digest per batch.

### 1.2 Key Features

- **Deterministic canonicalisation** — stable byte encoding across field order, date representation, null handling, Unicode normalisation, and supported numeric types.
- **Record digests** — SHA-256 digests over a versioned schema and canonical record representation.
- **RFC 6962 Merkle trees** — domain-separated leaf and node hashing with inclusion proofs.
- **Three-part batch commitments** — membership, interval, and continuity claims protect against modification, record deletion, and whole-batch deletion.
- **Degraded verification** — verification can still detect some failures when record-level witnesses are unavailable.
- **Multiple anchor backends** — in-memory, append-only JSON Lines file simulation, and EVM anchoring.
- **Two shipped domain profiles** — accounting journal entries and research-provenance instrument events.
- **CSV and SQLite ingestion** — explicit type coercion before canonicalisation.
- **Command-line workflow** — ingest, generate, deploy, anchor, verify, and benchmark.
- **Synthetic tamper benchmark** — reproducible generation and injection of four accounting attack classes with ground truth.
- **Reproducible experiment harness** — throughput, proof-size, detection, gas, and batch-size trade-off artifacts under `results/`.
- **Docker and CI support** — the repository includes a Dockerfile and GitHub Actions configuration.

### 1.3 Integrity Model

Each batch commitment binds three claims:

| Claim | What is committed | Main purpose |
|---|---|---|
| **Membership** | Merkle root and leaf count | Detect record modification and reordering |
| **Interval** | Sequence bounds and exact record count | Detect record deletion or insertion within the committed interval |
| **Continuity** | Digest of the previous batch commitment | Detect removal or substitution of a whole batch |

Only the commitment digest is authoritative at the anchoring layer. The record data, witnesses, and EVM commitment bodies can remain off-chain.

### 1.4 Evidence Levels During Verification

LedgerGuard verifies with the strongest available evidence and degrades when optional evidence is missing:

1. **Witness replay** can identify individual records whose digests no longer fit the committed Merkle root.
2. **Root comparison** proves that the current batch differs even if individual attribution is unavailable.
3. **Interval comparison** detects count shortfalls or surpluses from the committed sequence interval and record count.
4. **Continuity verification** checks that batches form the same committed chain.

A missing witness therefore reduces localisation precision; it does not automatically make every integrity check impossible. By contrast, loss or corruption of an EVM commitment body prevents interpretation of that batch and fails closed.

### 1.5 Technical Architecture

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Core runtime dependencies | None |
| Optional blockchain interface | `web3>=7.0` |
| Test framework | pytest / pytest-cov |
| Smart contract | Solidity `AnchorRegistry` artifact shipped with the package |
| Local anchor simulation | Append-only JSON Lines file |
| On-chain anchor | EVM-compatible chain via HTTP RPC |
| Packaging | Hatchling / PEP 621 (`pyproject.toml`) |
| CI | GitHub Actions |
| License | MIT |

### 1.6 Typical Use Cases

LedgerGuard can be used for:

- continuous or periodic integrity checking of accounting journal exports;
- tamper-evident research provenance and instrument event records;
- reproducible experiments on record-integrity controls;
- independent anchoring of batch commitments to an EVM chain;
- scheduled verification jobs that need machine-readable exit codes;
- development of additional domain profiles over the same integrity pipeline.

LedgerGuard proves consistency with previously anchored evidence. It does **not** prove that a record was truthful before it was anchored, and it does not replace access control, source-system validation, backup, or business-rule review.

---

## 2. System Requirements

### 2.1 Core Python Package

| Item | Requirement | Recommendation |
|---|---|---|
| Python | 3.10 or later | Current supported CPython release used by your environment |
| Operating system | Linux, macOS, or Windows | Any CI-supported platform |
| Core dependencies | None | Install development extras when testing |
| Disk | Small for the package itself | Allow additional space for ledgers, witnesses, results, and local anchors |
| Network | Not required for file backend | Required for remote EVM RPC |

### 2.2 Optional Dependency Groups

The project defines the following extras:

| Extra | Packages | Needed for |
|---|---|---|
| `evm` | `web3>=7.0` | Deploying or using the EVM backend |
| `dev` | pytest, pytest-cov, web3, eth-tester, matplotlib | Full development, tests, in-process EVM tests, experiment figures |

Install them from the repository root with:

```bash
pip install -e ".[evm]"
```

or:

```bash
pip install -e ".[dev]"
```

### 2.3 EVM Requirements

For a real chain connection you need:

- an EVM-compatible node or provider reachable over HTTP RPC;
- an account able to send the deployment or anchoring transaction;
- the deployed `AnchorRegistry` contract address for anchoring and verification.

No Solidity toolchain is required for ordinary use because the compiled contract artifact is shipped under `src/ledgerguard/artifacts/`.

### 2.4 Docker

Docker is optional. The repository includes a `Dockerfile` and `.dockerignore` for running the test suite or demonstration without managing a local Python environment.

---

## 3. Installation

### 3.1 Clone the Repository

Current repository:

```bash
git clone https://github.com/ZhangBin0209/ledgerguard.git
cd ledgerguard
```

### 3.2 Install the Core Package

For an editable source installation:

```bash
pip install -e .
```

The core package has no third-party runtime dependencies.

### 3.3 Install Development Support

For tests, figures, and the in-process EVM test environment:

```bash
pip install -e ".[dev]"
```

For EVM use without the full development toolchain:

```bash
pip install -e ".[evm]"
```

### 3.4 Verify the Installation

Check the installed version:

```bash
python -c "import ledgerguard; print(ledgerguard.__version__)"
```

Expected version for this manual:

```text
0.6.13
```

Run the test suite:

```bash
pytest -q
```

Some EVM-related tests may be skipped when optional dependencies are not installed. A skip caused by an intentionally absent optional dependency is different from a test failure.

Run the narrated demonstration:

```bash
python demo.py
```

### 3.5 Run with Docker

Build the image:

```bash
docker build -t ledgerguard .
```

Run the test suite:

```bash
docker run --rm ledgerguard
```

Run the demonstration:

```bash
docker run --rm ledgerguard demo
```

---

## 4. Functional Modules

### 4.1 Core Package Modules

| Module | Purpose |
|---|---|
| `ledgerguard.schema` | Versioned record schemas and field definitions |
| `ledgerguard.canonical` | Canonical byte encoding and record digests |
| `ledgerguard.merkle` | RFC 6962-style Merkle trees and inclusion proofs |
| `ledgerguard.commitment` | Batch construction, interval claims, witnesses, commitment chaining |
| `ledgerguard.backends` | Abstract backend, memory backend, file backend, anchor errors |
| `ledgerguard.verifier` | Batch and ledger verification and forensic reports |
| `ledgerguard.ingest` | CSV/SQLite reading and value coercion |
| `ledgerguard.evm` | EVM backend and contract deployment |
| `ledgerguard.synth` | Reproducible synthetic ledgers |
| `ledgerguard.tamper` | Controlled tamper injection for benchmarking |
| `ledgerguard.profiles.accounting` | Journal-entry schema and accounting rules |
| `ledgerguard.profiles.provenance` | Instrument-event schema and provenance rules |
| `ledgerguard.cli` | Command-line interface |

### 4.2 Schema and Canonicalisation

A `RecordSchema` fixes the schema identifier, version, field list, field types, and monotonic sequence field. Supported field types are:

- `STRING`
- `INTEGER`
- `MONEY`
- `DATE`
- `DATETIME`
- `BOOLEAN`

The schema identifier and version are incorporated into the digest space. A field-list change should therefore be accompanied by a schema-version change rather than silently reusing an existing version.

Canonicalisation is intentionally stricter than ordinary data conversion. For example, float monetary values are rejected rather than rounded, and naive datetimes are not silently assigned a timezone during canonical encoding.

### 4.3 Merkle Layer

`MerkleTree` builds a domain-separated tree over 32-byte record digests. It supports:

- root calculation;
- inclusion proofs by index;
- inclusion proofs by digest;
- proof verification and root reconstruction.

The implementation follows the RFC 6962 family of tree construction rather than the Bitcoin duplicate-last-leaf convention.

### 4.4 Commitment Layer

`BatchBuilder` accepts records in ascending sequence order and seals them into a `Batch`. A sealed batch exposes:

- the Merkle tree and root;
- the interval claim;
- the `BatchCommitment`;
- record-level inclusion proofs;
- a `BatchWitness` for later localisation.

`verify_chain()` checks the continuity links between commitments.

### 4.5 Backends

#### Memory backend

`MemoryBackend` is useful for tests and in-process use. It is not persistent.

#### File backend

`FileBackend` stores anchors as append-only JSON Lines. It is a simulator because the file can remain under the same administrative control as the ledger being protected.

Important behaviours include:

- duplicate anchors are refused;
- a missing store can be distinguished from an empty one;
- read-only verification does not modify the anchor file;
- a torn final line can be read around and reported;
- a writable handle can recover the torn tail before appending.

#### EVM backend

`EVMBackend` stores the authoritative commitment digest in an `AnchorRegistry` contract. The commitment body remains off-chain in a body store and is re-hashed when fetched.

### 4.6 Verification Module

`Verifier` compares observed records with the anchored commitments and optional witnesses. The main report objects are:

- `RecordFinding`
- `BatchReport`
- `LedgerReport`

Record verdicts include:

- `INTACT`
- `MODIFIED`
- `DELETED`
- `INSERTED`

Verification is read-only with respect to the anchor evidence used by the CLI.

### 4.7 Ingestion Module

LedgerGuard keeps **coercion** and **canonicalisation** separate:

1. ingestion converts source values to the Python types required by the schema;
2. canonicalisation converts those typed values to deterministic bytes.

Supported built-in sources are:

- CSV;
- SQLite table reads;
- SQLite queries;
- streaming SQLite reads with `iter_sqlite()`.

### 4.8 Synthetic Data and Tamper Injection

The research harness can generate reproducible synthetic accounting ledgers and provenance runs. For accounting data, `tamper.inject()` can apply controlled attack classes with ground-truth labels for benchmark scoring.

The benchmark is intended to test the software's ability to detect post-anchor changes, not to simulate every real-world fraud or attack mechanism.

---

## 5. Command-Line Reference

### 5.1 General Syntax

```bash
ledgerguard [--profile {accounting,provenance}] COMMAND [options]
```

Default profile: `accounting`.

Available commands:

| Command | Purpose |
|---|---|
| `ingest` | Read records from CSV or SQLite |
| `generate` | Produce a synthetic ledger |
| `deploy` | Deploy an `AnchorRegistry` contract |
| `anchor` | Batch, commit, and anchor a ledger |
| `verify` | Check a ledger against its anchors |
| `benchmark` | Measure detection rate by injected attack class |

Use:

```bash
ledgerguard --help
ledgerguard COMMAND --help
```

for the exact options supported by the installed version.

### 5.2 `generate`

```bash
ledgerguard generate [--vouchers N] [--seed N] [--batch-size N] [--void-rate R] [-o FILE]
```

Example:

```bash
ledgerguard generate --vouchers 500 --seed 1 -o ledger.json
```

The output is a synthetic ledger suitable for demonstrations and experiments.

### 5.3 `ingest`

```bash
ledgerguard ingest SOURCE [--table TABLE | --query SQL] [--assume-utc] [-o FILE]
```

Examples:

```bash
ledgerguard ingest export.csv -o ledger.json
```

```bash
ledgerguard ingest erp.db --table gl_journal -o ledger.json
```

```bash
ledgerguard ingest erp.db --query "SELECT * FROM gl_journal WHERE period='2026-03'" -o ledger.json
```

For provenance data containing naive source timestamps that are known to represent UTC:

```bash
ledgerguard --profile provenance ingest runs.db --table events --assume-utc -o events.json
```

### 5.4 `anchor`

File backend:

```bash
ledgerguard anchor ledger.json --batch-size 100
```

By default the file backend uses local anchor and witness files. It is suitable for development and demonstration but should not be treated as independent evidence when it shares the same trust boundary as the ledger.

Custom file locations:

```bash
ledgerguard anchor ledger.json \
  --backend file \
  --anchors anchors.jsonl \
  --witnesses witnesses.json \
  --batch-size 100
```

EVM backend:

```bash
ledgerguard anchor ledger.json \
  --backend evm \
  --rpc http://localhost:8545 \
  --contract 0xYOUR_CONTRACT \
  --body-store bodies.jsonl \
  --witnesses witnesses.json \
  --batch-size 100
```

### 5.5 `verify`

File backend:

```bash
ledgerguard verify ledger.json
```

JSON report:

```bash
ledgerguard verify ledger.json --json
```

EVM backend:

```bash
ledgerguard verify ledger.json \
  --backend evm \
  --rpc http://localhost:8545 \
  --contract 0xYOUR_CONTRACT \
  --body-store bodies.jsonl
```

The exit status is part of the CLI contract:

| Exit code | Meaning |
|---|---|
| `0` | Ledger matches the available anchors |
| `1` | A discrepancy was detected |
| `2` | Verification could not be completed meaningfully |

Examples of exit code `2` include a missing/empty anchor store, an unreadable anchor source, an unavailable EVM node, or a situation in which every anchor belongs to a different schema/profile.

### 5.6 `deploy`

Install the EVM extra first:

```bash
pip install -e ".[evm]"
```

Deploy the registry:

```bash
ledgerguard deploy --rpc http://localhost:8545
```

Optionally choose a sender:

```bash
ledgerguard deploy --rpc http://localhost:8545 --account 0xYOUR_ACCOUNT
```

The command prints the deployed contract address. Preserve that address as part of the verification context.

### 5.7 `benchmark`

```bash
ledgerguard benchmark --vouchers 500 --seed 1 --batch-size 100
```

Attack counts can be controlled with:

- `--amount`
- `--deletion`
- `--period`
- `--sequence`

The benchmark uses synthetic accounting data and known injected manipulations so that detection results can be scored against ground truth.

---

## 6. Python API Reference

### 6.1 Schema

```python
FieldSpec(name, type, nullable=False, scale=None, strip=True)
RecordSchema(schema_id, version, fields, sequence_field)
```

Primary types:

```python
from ledgerguard import FieldSpec, FieldType, RecordSchema
```

A custom schema must have a stable `schema_id`/`version` pair and a non-nullable integer sequence field.

### 6.2 Canonicalisation and Digests

```python
canonical_preimage(record, schema) -> bytes
record_digest(record, schema) -> bytes
record_digest_hex(record, schema) -> str
```

Use `canonical_preimage()` when an exact disputed preimage must be inspected. Use `record_digest()` or `record_digest_hex()` for integrity operations.

### 6.3 Merkle API

```python
MerkleTree(digests)
```

Important members:

```python
tree.root
tree.root_hex
tree.prove(index)
tree.prove_digest(digest)
```

An `InclusionProof` provides:

```python
proof.recompute_root()
proof.verify(root)
```

### 6.4 Batch Commitments

```python
BatchBuilder(schema, batch_id, prev_digest)
```

Typical flow:

```python
builder = BatchBuilder(schema, batch_id="batch-0001", prev_digest=GENESIS_DIGEST)
builder.extend(records)
batch = builder.seal()
commitment = batch.commitment
witness = batch.witness()
```

Useful operations:

```python
batch.prove_sequence(seq)
commitment.digest()
commitment.digest_hex()
commitment.to_dict()
witness.verify_against(commitment)
check_interval(commitment, observed, schema)
verify_chain(commitments)
```

### 6.5 Backends

Common interface:

```python
backend.anchor(commitment)
backend.fetch(batch_id)
backend.latest()
backend.next_prev_digest()
backend.chain()
```

Available implementations:

```python
MemoryBackend()
FileBackend(path, create=True, read_only=False)
EVMBackend(...)
```

Backend errors include:

- `AnchorError`
- `DuplicateAnchorError`
- `CorruptAnchorError`
- `MissingAnchorStoreError`

The EVM module additionally defines `MissingDependencyError` when `web3` is not installed.

### 6.6 Verification

```python
Verifier(backend, schema)
```

Batch verification:

```python
report = verifier.verify_batch(batch_id, observed_records, witness=witness)
```

Whole-ledger verification:

```python
report = verifier.verify_ledger(observed_records, witnesses=witness_map)
```

Inspect the report:

```python
report.intact
report.summary()
report.count(Verdict.MODIFIED)
report.to_dict()
```

Human-readable rendering:

```python
from ledgerguard import format_report
print(format_report(report))
```

### 6.7 Ingestion

CSV:

```python
from ledgerguard.ingest import read_csv
records = read_csv("export.csv", schema)
```

SQLite table:

```python
from ledgerguard.ingest import read_sqlite
records = read_sqlite("erp.db", schema, table="gl_journal")
```

SQLite query:

```python
records = read_sqlite(
    "erp.db",
    schema,
    query="SELECT * FROM gl_journal WHERE period = ? ORDER BY line_seq",
    parameters=("2026-03",),
)
```

Streaming large tables:

```python
from ledgerguard.ingest import iter_sqlite

for batch in iter_sqlite(connection, schema, table="gl_journal", batch_size=1000):
    ...
```

Column mapping:

```python
records = read_csv(
    "export.csv",
    schema,
    columns={
        "line_seq": "ID",
        "voucher_no": "DOC_NO",
        "debit": "DR_AMT",
    },
)
```

### 6.8 EVM Backend

```python
from web3 import Web3
from ledgerguard.backends import FileBackend
from ledgerguard.evm import EVMBackend

w3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
chain = EVMBackend.deploy(w3, body_store=FileBackend("bodies.jsonl"))
chain.anchor(batch.commitment)
```

For tests without an external node:

```python
chain = EVMBackend.in_memory_chain()
```

### 6.9 Synthetic Research Helpers

Accounting ledger:

```python
from ledgerguard import synth
ledger = synth.generate(seed=1)
```

Provenance data:

```python
runs = synth.generate_provenance(runs=50, seed=1)
```

Tamper injection:

```python
from ledgerguard import tamper
result = tamper.inject(records, seed=1, amount=1, deletion=1, period=1, sequence=1)
```

The returned object contains both the altered records and a ground-truth tamper log.

---

## 7. Operation Guide

### 7.1 Five-Minute Local Demonstration

Generate data:

```bash
ledgerguard generate --vouchers 500 --seed 1 -o ledger.json
```

Anchor it locally in 100-record batches:

```bash
ledgerguard anchor ledger.json --batch-size 100
```

Verify it:

```bash
ledgerguard verify ledger.json
```

An unchanged ledger should return exit code `0`.

### 7.2 Demonstrate Detection

Create a tampered copy with the package API:

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
```

Verify the altered copy against the original anchors:

```bash
ledgerguard verify tampered.json
```

A detected discrepancy returns exit code `1`.

### 7.3 Verify from a Real SQLite Database

Initial capture:

```bash
ledgerguard ingest erp.db --table gl_journal -o ledger.json
ledgerguard anchor ledger.json --batch-size 100
```

At a later time:

```bash
ledgerguard ingest erp.db --table gl_journal -o current.json
ledgerguard verify current.json
```

For scheduled checking, use the process exit code rather than parsing human-readable text.

### 7.4 Use the Provenance Profile

The CLI can generate the shipped provenance profile directly. For this profile, `--vouchers` is interpreted as the number of instrument runs:

```bash
ledgerguard --profile provenance generate --vouchers 50 --seed 1 -o provenance.json
```

Then anchor and verify with the same profile selected:

```bash
ledgerguard --profile provenance anchor provenance.json --batch-size 100
ledgerguard --profile provenance verify provenance.json
```

The equivalent Python generator is `ledgerguard.synth.generate_provenance()`. Profile selection must match the schema under which the anchors were originally created.

### 7.5 Anchor to an EVM Chain

Install support:

```bash
pip install -e ".[evm]"
```

Deploy a registry:

```bash
ledgerguard deploy --rpc http://localhost:8545
```

Assume the printed address is `0xREGISTRY`.

Anchor:

```bash
ledgerguard anchor ledger.json \
  --backend evm \
  --rpc http://localhost:8545 \
  --contract 0xREGISTRY \
  --body-store bodies.jsonl \
  --batch-size 100
```

Verify:

```bash
ledgerguard verify ledger.json \
  --backend evm \
  --rpc http://localhost:8545 \
  --contract 0xREGISTRY \
  --body-store bodies.jsonl
```

### 7.6 Preserve Verification Context

For meaningful long-term verification, preserve at least:

- the schema/profile name and version;
- the deployed contract address or trusted file-anchor location;
- the RPC trust model when using a chain;
- the off-chain commitment body store when using EVM;
- witnesses if record-level localisation is desired;
- the software/schema version needed to interpret historical commitments.

The contract address is part of the evidence context. A digest on an unrelated registry is not automatically evidence for your organisation.

### 7.7 Reproduce the Shipped Experiments

Run:

```bash
python scripts/experiments.py --out results/
```

For the multi-run throughput measurement used by the repository's generated README section:

```bash
python scripts/experiments.py --runs 3 --out results/
```

The harness writes CSV outputs and figures under `results/`. Absolute throughput depends on hardware and should be re-measured before being quoted for a different machine.

---

## 8. Profiles and Data Requirements

### 8.1 Accounting Profile

Schema ID: `accounting.journal_entry`  
Version: `1`  
Sequence field: `line_seq`

Fields:

| Field | Type | Notes |
|---|---|---|
| `line_seq` | INTEGER | Global monotonic sequence |
| `voucher_no` | STRING | Human-facing voucher/document identifier |
| `line_no` | INTEGER | Line number within the voucher |
| `period` | STRING | Accounting period |
| `posting_date` | DATE | Posting date |
| `account_code` | STRING | Account identifier |
| `debit` | MONEY(2) | Debit amount |
| `credit` | MONEY(2) | Credit amount |
| `currency` | STRING | Currency code or source-system value |
| `description` | STRING, nullable | Optional description |
| `preparer` | STRING | Preparer identifier |
| `document_ref` | STRING, nullable | Optional external reference |

Domain checks implemented by the profile include:

- amounts must not be negative;
- a line must carry an amount on exactly one side;
- vouchers must balance per currency;
- duplicate sequence values are not accepted for sequence-interval analysis.

Voucher numbers are not used as the global sequence field because real systems may legitimately contain gaps from voided or reserved documents.

### 8.2 Provenance Profile

Schema ID: `provenance.instrument_event`  
Version: `1`  
Sequence field: `event_seq`

Fields:

| Field | Type | Notes |
|---|---|---|
| `event_seq` | INTEGER | Global monotonic event sequence |
| `run_id` | STRING | Instrument-run identifier |
| `event_type` | STRING | Run lifecycle event |
| `recorded_at` | DATETIME | Timestamp normalised by schema rules |
| `instrument_id` | STRING | Instrument identifier |
| `operator` | STRING | Operator identifier |
| `sample_id` | STRING, nullable | Required for sample load/measurement events |
| `artifact_digest` | STRING, nullable | Lowercase SHA-256 hex when present |
| `parameters` | STRING, nullable | Optional parameters |
| `is_automated` | BOOLEAN | Automated/manual flag |

Supported event kinds are:

- `run_start`
- `sample_loaded`
- `calibration`
- `measurement`
- `artifact_written`
- `run_end`

Domain checks include chronological ordering by sequence, calibration before dependent events, required sample identifiers, and well-formed artefact digests.

### 8.3 CSV Requirements

The default encoding is `utf-8-sig`, which tolerates spreadsheet-export byte-order marks.

Source columns may be remapped to schema fields. Values are coerced before canonicalisation.

### 8.4 SQLite Requirements

For table reads, LedgerGuard orders rows numerically by the schema sequence field. This avoids the common SQLite problem in which values stored as text sort as `1, 10, 100, 2`.

Use a query when filtering or source-side casting is required.

### 8.5 Null Values

For nullable fields, common source markers such as an empty value, `NULL`, `none`, or `\N` are interpreted as null during ingestion. Non-nullable fields reject null markers.

Be aware that a nullable string whose legitimate literal content is `"None"` may therefore need explicit source remapping or preprocessing.

### 8.6 Monetary Values

Floating-point monetary inputs are rejected. Use exact decimal strings, integers where appropriate, or source-side casting to text. This prevents a binary floating-point approximation from being silently turned into a plausible but different committed value.

### 8.7 Dates and Datetimes

- `DATE` accepts a valid date and can narrow a naive timestamp to its calendar date when appropriate.
- zoned timestamps should not be silently converted into dates because the resulting calendar date depends on timezone;
- naive `DATETIME` values require an explicit assumption such as `assume_utc=True` when the source semantics justify it.

### 8.8 Writing a New Profile

A profile is a schema plus domain-specific validation rules. Example:

```python
from ledgerguard.schema import FieldSpec, FieldType, RecordSchema

SHIPMENT_EVENT_V1 = RecordSchema(
    schema_id="logistics.shipment_event",
    version=1,
    sequence_field="event_seq",
    fields=(
        FieldSpec("event_seq", FieldType.INTEGER),
        FieldSpec("consignment_id", FieldType.STRING),
        FieldSpec("occurred_at", FieldType.DATETIME),
        FieldSpec("location", FieldType.STRING),
        FieldSpec("custodian", FieldType.STRING),
        FieldSpec("sealed", FieldType.BOOLEAN),
        FieldSpec("notes", FieldType.STRING, nullable=True),
    ),
)
```

Register the profile under `ledgerguard.profiles` and keep domain-specific validation in the profile layer. A new profile should not require changes to canonicalisation, Merkle, commitments, backends, or verification.

---

## 9. Verification, Validation, and Reproducibility

### 9.1 Frozen Wire-Format Vectors

`tests/vectors.json` contains frozen expected digests, preimage hashes, Merkle roots, and commitment values. These vectors protect long-term compatibility: a change in canonical encoding that silently changes historical digests should fail the suite rather than invalidate old anchors unnoticed.

If an incompatible encoding must be introduced, use a new schema version instead of changing the meaning of an existing version.

### 9.2 Test Suite

Run:

```bash
pytest -q
```

The test suite covers canonicalisation, commitments, Merkle proofs, backends, ingestion, profiles, verification, CLI behaviour, EVM integration when available, experiment aggregation, and frozen vectors.

Optional EVM dependencies affect which tests can run in a given environment. Treat a test failure as a defect to investigate; treat a documented optional-dependency skip separately.

### 9.3 Mutation Checks

The repository contains a hand-curated security mutation script:

```bash
python scripts/mutate.py
```

Its purpose is to verify that the suite detects deliberately introduced integrity/security regressions rather than only exercising happy paths.

### 9.4 Contract Artifact Check

The compiled `AnchorRegistry` artifact is shipped with the package. If the Solidity compilation environment is available, the repository provides:

```bash
python scripts/compile_contract.py --check
```

This checks that the shipped artifact corresponds to the contract source.

### 9.5 Shipped Performance Artifacts

The `results/` directory contains the measurements used by the repository documentation. For version 0.6.13, the shipped README reports:

| Property | Shipped measurement context |
|---|---|
| Anchoring throughput | Approximately 42,900–45,200 records/s on the recorded test environment |
| Verification throughput | Approximately 17,500–18,200 records/s with full witness replay |
| Commitment digest | 32 bytes per batch |
| EVM gas per anchoring transaction | Approximately 119,596–119,608 for tested batch sizes of 10–5,000, with a higher first transaction on a fresh registry |
| Inclusion proof | 14 hashes / 448 bytes at 16,384 records |
| Injected-tamper detection experiment | 1,607 injected manipulations across 20 seeded runs; shipped results report full recall and no false positives for the implemented attack classes |

These are reproducibility artifacts, not hardware-independent guarantees. Re-run the harness on the deployment environment before using absolute throughput or timing values for capacity planning.

### 9.6 Security Meaning of the Detection Benchmark

A 100% result in the shipped synthetic manipulation benchmark should not be interpreted as a general fraud-detection rate. The benchmark measures whether cryptographic commitments detect the classes of post-anchor manipulation that the harness intentionally injects.

It does not measure:

- whether false business data was originally entered before anchoring;
- insider collusion before commitment;
- semantic fraud that leaves committed record bytes unchanged;
- availability of the RPC provider or body store;
- compromise of the user's verification environment.

### 9.7 EVM Trust Boundaries

The EVM contract is append-only and has no update/delete override. However:

- the verifier still trusts its view of the chain;
- a single untrusted RPC provider can misrepresent that view;
- the registry address must be independently known and preserved;
- a shared public registry can expose batch-ID contention, even though an attacker cannot forge the expected commitment digest;
- the off-chain body store must remain available, although its integrity is checked against the on-chain digest.

For higher assurance, use a node you control, a light client, or independent RPC cross-checking appropriate to your environment.

### 9.8 Scope and Limitations

- LedgerGuard detects changes **after** anchoring, not false data created before anchoring.
- Anchoring frequency is therefore a security parameter.
- The file backend is not an independent trust anchor when stored under the same control as the protected ledger.
- Witness loss reduces record-level attribution but can leave other checks available.
- EVM commitment-body loss prevents interpretation of the associated batch and fails closed.
- A public digest of sufficiently low-entropy content may leak information through enumeration; salted record digests are not part of version 0.6.13.
- LedgerGuard supplies integrity evidence. Human auditors must interpret findings in the surrounding business, research, or regulatory context.

---

## 10. Troubleshooting

### 10.1 `ledgerguard` Command Is Not Found

**Cause:** the package is not installed in the active environment or the environment's script directory is not on `PATH`.

**Fix:**

```bash
python -m pip install -e .
```

Then reopen the shell if needed and run:

```bash
ledgerguard --help
```

### 10.2 EVM Command Says `web3` Is Missing

**Cause:** only the dependency-free core was installed.

**Fix:**

```bash
pip install -e ".[evm]"
```

For the full development stack:

```bash
pip install -e ".[dev]"
```

### 10.3 Verification Returns Exit Code `2`

Exit code `2` means the program could not establish a meaningful integrity comparison, rather than that it proved the ledger clean or tampered.

Check for:

- a wrong or missing `--anchors` path;
- an empty anchor store;
- wrong working directory;
- unavailable RPC endpoint;
- wrong contract address;
- all anchors having been created under a different profile/schema;
- an unreadable or corrupt commitment body store.

Do not treat exit code `2` as a pass.

### 10.4 Every Batch Appears to Be Under the Wrong Schema

**Cause:** verification is using the wrong profile.

**Fix:** use the same profile that was used during anchoring:

```bash
ledgerguard --profile accounting verify ledger.json
```

or:

```bash
ledgerguard --profile provenance verify events.json
```

### 10.5 SQLite Records Are in the Wrong Order

Use the built-in table reader or explicitly order a custom query by the numeric sequence field. Text-stored numbers can otherwise sort lexicographically.

Example:

```sql
SELECT * FROM gl_journal ORDER BY CAST(line_seq AS INTEGER)
```

### 10.6 A Monetary Column Is Rejected as `float`

**Cause:** the source adapter has already converted an exact monetary value into binary floating point.

**Fix:** cast the field to text in the query, export exact decimal text, or store minor units as integers. Do not suppress the error by round-tripping through `float`.

### 10.7 A Naive Timestamp Is Rejected

**Cause:** its timezone is not defined.

If the source is known to store UTC, use:

```bash
ledgerguard --profile provenance ingest source.db --table events --assume-utc -o events.json
```

In Python, pass `assume_utc=True` to the ingestion function.

Only do this when the source-system semantics justify the assumption.

### 10.8 Verification Detects a Root Mismatch but Cannot Name the Record

**Cause:** the witness is unavailable, invalid, or does not match the anchored commitment.

The root mismatch can still show that the batch changed, and interval evidence may still identify a count discrepancy. Restore the original valid witness if record-level localisation is required.

### 10.9 A Witness Is Rejected

LedgerGuard verifies the witness against the anchored commitment before using it to accuse individual records. A modified, mismatched, or corrupt witness is therefore rejected rather than trusted.

Use the witness produced for the same batch at anchoring time.

### 10.10 The Anchor File Ends with an Incomplete JSON Line

A process interruption can leave a torn final line. Read-only verification reports and reads around the torn tail without rewriting the evidence. A later writable anchoring operation can recover the tail before appending.

Preserve the file if forensic review of the interruption is required.

### 10.11 An Anchor Is Reported as Duplicate

A batch identifier already exists in the selected backend. LedgerGuard refuses to overwrite it.

Confirm that:

- you are using the intended registry or file;
- the batch ID/prefix is correct;
- the previous anchoring operation did not already succeed.

On a shared public registry, a third party may occupy a batch ID first. A dedicated registry per organisation avoids this namespace contention.

### 10.12 The EVM Body Store Is Missing or Corrupt

Only the digest is stored on chain. The commitment body is needed to interpret the digest during verification.

If the body is missing or no longer hashes to the on-chain value, the EVM backend fails closed. Restore the correct body store from protected backup.

### 10.13 Absolute Throughput Does Not Match the Repository

This is expected across different CPUs, virtual machines, Python builds, and background load.

Run:

```bash
python scripts/experiments.py --runs 3 --out results/
```

and use the measurements from your own deployment environment.

### 10.14 Tests Are Skipped

Optional EVM tests can be skipped when `web3`, `eth-tester`, or its EVM backend is unavailable.

Install development extras:

```bash
pip install -e ".[dev]"
```

Then run the suite again. A skip is not equivalent to a failure, but the reason for the skip should be understood before claiming that optional functionality was tested locally.

---

## 11. Support and Version Information

### 11.1 Repository

- **Repository:** https://github.com/ZhangBin0209/ledgerguard
- **Issue tracker:** https://github.com/ZhangBin0209/ledgerguard/issues

### 11.2 Version

- **Current version:** 0.6.13
- **Python:** 3.10+
- **License:** MIT
- **Core runtime dependencies:** none
- **Optional EVM dependency:** web3

### 11.3 Author

**Zhang Bin**  
School of Digital Intelligence Finance & Business (数智财商学院)  
Anhui Technical College of Industry and Economy (安徽工业经济职业技术学院)  
Email: zhangbin_0209@126.com

### 11.4 Citation

Machine-readable citation metadata is provided in `CITATION.cff`.

If the software is used in academic work, cite the software release/version actually used so that the relevant wire format, test vectors, and experimental artifacts can be identified.

### 11.5 License

LedgerGuard is distributed under the MIT License. See `LICENSE` for the complete terms.

### 11.6 Related Documentation

More focused documentation is available under `docs/`:

- `docs/getting-started.md` — short installation and workflow guide;
- `docs/concepts.md` — integrity model and commitment concepts;
- `docs/ingestion.md` — CSV/SQLite coercion and data handling;
- `docs/profiles.md` — shipped profiles and profile extension;
- `docs/api.md` — concise public API reference;
- `docs/chain.md` — EVM contract, backend, cost, and trust model.

---

## 12. Appendix

### A. Public API Summary

**Schema**

- `FieldType`
- `FieldSpec`
- `RecordSchema`

**Canonicalisation**

- `canonical_preimage`
- `record_digest`
- `record_digest_hex`

**Merkle**

- `leaf_hash`
- `node_hash`
- `MerkleTree`
- `InclusionProof`

**Commitments**

- `GENESIS_DIGEST`
- `Interval`
- `BatchCommitment`
- `BatchWitness`
- `Batch`
- `BatchBuilder`
- `IntervalFinding`
- `check_interval`
- `verify_chain`

**Backends**

- `ChainBackend`
- `MemoryBackend`
- `FileBackend`
- `AnchorRecord`
- `AnchorError`
- `DuplicateAnchorError`
- `CorruptAnchorError`
- `MissingAnchorStoreError`

**Verification**

- `Verifier`
- `LedgerReport`
- `BatchReport`
- `RecordFinding`
- `Verdict`
- `BatchStatus`
- `format_report`

**Ingestion**

- `coerce_value`
- `coerce_record`
- `read_csv`
- `read_sqlite`
- `iter_sqlite`
- `write_sqlite`
- `IngestError`

**Profiles**

- `get_profile`
- `profile_names`

**Research helpers**

- `synth.generate`
- `synth.generate_provenance`
- `tamper.inject`
- `tamper.inject_proportional`

**EVM**

- `EVMBackend`
- `EVMBackend.deploy`
- `EVMBackend.in_memory_chain`
- `load_artifact`

### B. CLI Exit Codes

| Command | Exit code | Meaning |
|---|---:|---|
| `verify` | 0 | Verified with no discrepancy |
| `verify` | 1 | Discrepancy detected |
| `verify` | 2 | Could not verify meaningfully |
| `anchor` | 2 | Empty ledger or an operational condition that prevents anchoring |

Other command failures may return non-zero status depending on the encountered input, backend, or environment error.

### C. Common Files Produced by a Local Workflow

| File | Purpose |
|---|---|
| `ledger.json` | Typed/canonicalisable ledger records used by the CLI |
| `anchors.jsonl` | File-backend anchor simulator |
| `witnesses.json` | Record-level digest witnesses for localisation |
| `bodies.jsonl` | Off-chain commitment bodies for EVM anchoring |
| `results/*.csv` | Reproducible experiment outputs |
| `results/*.png` / `*.pdf` | Experiment figures |

File names can be changed with the corresponding CLI options.

### D. Repository Layout

```text
ledgerguard/
├── src/ledgerguard/                 # Python package
│   ├── schema.py                    # schema primitives
│   ├── canonical.py                 # canonical encoding and record hashes
│   ├── merkle.py                    # Merkle tree and proofs
│   ├── commitment.py                # batch commitments and witnesses
│   ├── backends.py                  # memory/file backend abstractions
│   ├── verifier.py                  # forensic verification reports
│   ├── ingest.py                    # CSV/SQLite ingestion
│   ├── evm.py                       # EVM backend
│   ├── synth.py                     # synthetic data generation
│   ├── tamper.py                    # controlled tamper injection
│   ├── cli.py                       # command-line interface
│   ├── profiles/
│   │   ├── accounting.py
│   │   └── provenance.py
│   └── artifacts/AnchorRegistry.json
├── contracts/AnchorRegistry.sol     # Solidity source
├── docs/                            # focused documentation
├── examples/                        # runnable examples
├── scripts/                         # experiments, mutation, contract/readme checks
├── tests/                           # pytest suite and frozen vectors
├── results/                         # shipped reproducibility artifacts
├── demo.py                          # narrated demonstration
├── pyproject.toml                   # package metadata
├── CITATION.cff                     # citation metadata
├── USER_MANUAL.md                   # consolidated user manual
├── README.md                        # project overview
├── CHANGELOG.md                     # release history
├── Dockerfile
└── LICENSE
```

### E. Recommended First-Time Workflow

For a new evaluator who wants the shortest path through the software:

```bash
# 1. install
pip install -e ".[dev]"

# 2. test
pytest -q

# 3. run the narrated demonstration
python demo.py

# 4. create a reproducible ledger
ledgerguard generate --vouchers 500 --seed 1 -o ledger.json

# 5. anchor locally for evaluation
ledgerguard anchor ledger.json --batch-size 100

# 6. verify
ledgerguard verify ledger.json

# 7. inspect the full research harness if needed
python scripts/experiments.py --out results/
```

For production-style independent evidence, replace the local file anchor with an independently controlled backend such as the supplied EVM path and preserve the contract address, body store, witnesses, schema/profile, and software version as part of the audit context.

---

*LedgerGuard 0.6.13 · MIT License · Zhang Bin · School of Digital Intelligence Finance & Business, Anhui Technical College of Industry and Economy*
