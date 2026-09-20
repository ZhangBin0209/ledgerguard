# API reference

## Schema

- `RecordSchema(schema_id, version, fields, sequence_field)` — a versioned
  field list. Both id and version are folded into every digest.
- `FieldSpec(name, type, nullable, scale, strip)` — one field. `scale` is
  required for `MONEY` and forbidden otherwise.
- `FieldType` — `STRING`, `INTEGER`, `MONEY`, `DATE`, `DATETIME`, `BOOLEAN`.

## Digests

- `record_digest(record, schema) -> bytes` — 32 bytes.
- `canonical_preimage(record, schema) -> bytes` — the exact bytes hashed,
  exposed so a disputed digest can be inspected rather than only re-hashed.

## Merkle

- `MerkleTree(digests)` — `.root`, `.prove(index)`, `.prove_digest(digest)`.
- `InclusionProof` — `.verify(root)`, `.recompute_root()`.

## Commitments

- `BatchBuilder(schema, batch_id, prev_digest)` — `.add()`, `.extend()`,
  `.seal()`. Records must arrive in ascending sequence order.
- `Batch` — `.commitment`, `.witness()`, `.prove_sequence(seq)`.
- `BatchCommitment` — `.digest()`, `.preimage()`, `.to_dict()`.
- `BatchWitness` — `.verify_against(commitment)`, `.digest_of(seq)`.
- `check_interval(commitment, observed, schema) -> IntervalFinding`
- `verify_chain(commitments)` — raises `ValueError` on a broken chain.

## Backends

- `ChainBackend` — `.anchor()`, `.fetch()`, `.__iter__()`, plus
  `.next_prev_digest()` and `.chain()`.
- `MemoryBackend()`.
- `FileBackend(path, *, create=True, read_only=False)` — an append-only
  JSON Lines simulator. `create=False` raises `MissingAnchorStoreError`
  instead of creating an absent store; `read_only=True` never writes
  (`.anchor()` is refused). Every read reads around a torn final line and
  sets `.torn_tail` from the file as it stands at that moment, so a handle
  sees repairs and appends made after it was opened. A writable handle
  repairs the tail at open (`.recovered`) and again before each append.
  Verification opens stores with `create=False, read_only=True`. A path
  that is a directory is refused with `AnchorError`.
- `EVMBackend(w3, address, account, body_store)`, `EVMBackend.deploy(w3)`,
  `EVMBackend.in_memory_chain()` — `.last_gas_used`, `.estimate_gas()`.
- Errors: `AnchorError` and its subclasses `DuplicateAnchorError`,
  `CorruptAnchorError`, `MissingAnchorStoreError`.

## Verification

- `Verifier(backend, schema)` — `.verify_batch()`, `.verify_ledger()`.
- `LedgerReport` — `.intact`, `.summary()`, `.count(verdict)`, `.to_dict()`.
- `Verdict` — `INTACT`, `MODIFIED`, `DELETED`, `INSERTED`.
- `format_report(report) -> str`

## Ingestion

- `read_csv(path, schema, columns, assume_utc)`
- `read_sqlite(database, schema, table | query, ...)`
- `iter_sqlite(connection, schema, ..., batch_size)` — streaming.
- `coerce_value(value, spec)`, `coerce_record(row, schema, columns)`

## Research helpers

- `synth.generate(...)`, `synth.generate_provenance(...)` — seeded and
  reproducible.
- `tamper.inject(records, seed, amount, deletion, period, sequence)` — returns
  a tampered ledger plus ground truth.
- `tamper.inject_proportional(records, rate, seed)`

## Command line

`ledgerguard [--profile NAME] {ingest,generate,deploy,anchor,verify,benchmark}`.
`anchor` and `verify` take `--backend {file,evm}` with `--anchors PATH` (file)
or `--rpc URL --contract ADDRESS [--account ADDRESS] [--body-store PATH]`
(evm). Exit status: `verify` returns 0 when the ledger matches its anchors,
1 on any discrepancy, and 2 when it could not verify at all — no anchor
store, an empty or unreadable one, a node that does not answer, or every
anchor made under a different schema. `anchor` returns 2 for an empty
ledger. Verification never writes to the anchor store.
