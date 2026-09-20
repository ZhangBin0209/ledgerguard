# LedgerGuard

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22854960.svg)](https://doi.org/10.5281/zenodo.22854960)

Tamper evidence for append-only structured records, with blockchain anchoring
and auditor-facing verification.

**Status: feature-complete.** 402 tests including frozen wire-format
vectors, 94% coverage, 26/26 hand-curated security mutants killed, lint- and
type-clean. Two shipped domain profiles, ingestion from CSV and SQLite,
simulated and on-chain anchoring from both the API and the command line, and
a reproducible experiment harness.

Zero runtime dependencies for the core; `web3` only for on-chain anchoring.
Python 3.10+.

## What is here

| Module | Role |
|---|---|
| `schema.py` | Generic, domain-independent record schema |
| `canonical.py` | Canonical encoding and digest computation |
| `merkle.py` | RFC 6962 Merkle tree and inclusion proofs |
| `commitment.py` | Batch commitments: membership, interval, continuity |
| `backends.py` | Pluggable anchoring backends and two simulators |
| `verifier.py` | Forensic reports at three levels of evidence |
| `synth.py` | Reproducible synthetic ledger generation |
| `tamper.py` | Four attack classes with ground-truth labels |
| `ingest.py` | Reading records from CSV and SQLite |
| `evm.py` | EVM backend, the only chain-specific code |
| `cli.py` | `ingest` / `generate` / `deploy` / `anchor` / `verify` / `benchmark` |
| `profiles/accounting.py` | Journal-entry schema, balance rules, sequence intervals |
| `profiles/provenance.py` | Instrument-run events, custody and calibration rules |
| `contracts/AnchorRegistry.sol` | Append-only anchor registry, one 32-byte digest per batch |
| `scripts/experiments.py` | Five experiments producing CSV and figures |
| `scripts/architecture_figure.py` | Source of the architecture figure (Fig. 1 of the paper) |
| `scripts/sync_readme.py` | Generates the "Measured behaviour" section below from `results/`; CI checks it |

The two-layer split is deliberate, and the second profile is what makes it
checkable rather than merely asserted. `accounting` and `provenance` share no
field name — only the requirement that some field carries a monotonic sequence
— and the entire integrity pipeline (`schema`, `canonical`, `merkle`,
`commitment`, `backends`, `evm`, `verifier`, `ingest`) runs on both with
nothing changed and imports nothing from `profiles/`. The harness modules are
the exception by design: `synth` knows both profiles in order to generate
for them, `tamper` is written against the accounting one because its attack
classes only mean something there, and `cli` binds profile names to `--profile`.
Any abstraction looks general when it has exactly one client.

## Quick start

```bash
pip install -e ".[dev]"
pytest                                    # 402 tests
python scripts/mutate.py                  # 26/26 hand-curated security mutants killed
python demo.py                            # anchoring and four attacks, narrated

# from a real database, or synthetically
ledgerguard ingest erp.db --table gl_journal -o ledger.json
ledgerguard generate --vouchers 500 -o ledger.json
ledgerguard anchor ledger.json --batch-size 100     # file simulator by default
ledgerguard verify ledger.json            # exit 0 clean, 1 tampered, 2 cannot verify; never writes
ledgerguard benchmark --vouchers 500      # detection rate per attack class

# the same, anchored to an AnchorRegistry contract
ledgerguard deploy --rpc http://localhost:8545      # prints the address
ledgerguard anchor ledger.json --backend evm --rpc http://localhost:8545 --contract 0x…
ledgerguard verify ledger.json --backend evm --rpc http://localhost:8545 --contract 0x…

python scripts/experiments.py --out results/   # reproduce every reported figure
```

The default `--backend file` is a simulator: an append-only file under the
same control as the ledger, right for experiments and teaching and wrong for
the threat the tool exists for. Anchoring to a chain needs
`pip install 'ledgerguard[evm]'`; the test suite runs a real EVM in process
via `eth-tester`, so no node is required to evaluate the software.
`docker run --rm ledgerguard` runs the suite with no local Python
environment at all.

Full documentation is in [`docs/`](docs/index.md); three runnable examples are
in [`examples/`](examples/). A consolidated user manual is available in [`USER_MANUAL.md`](USER_MANUAL.md).

## Design notes

**Canonicalisation.** The same record exported from two systems is rarely
byte-identical: field order, monetary precision, date formats, null encoding
and Unicode normalisation all vary. The canonical encoding fixes each of
these, and length-prefixes every element so that no two distinct records can
collide by concatenation. Float amounts and excess precision are rejected
rather than silently rounded.

**RFC 6962, not Bitcoin.** Leaves and internal nodes carry distinct hash
prefixes, blocking the second-preimage attack on unprefixed trees. Odd levels
split at the largest power of two rather than duplicating the last node,
avoiding the Bitcoin variant's duplicate-leaf ambiguity.

**Three claims, not one.** A Merkle root proves that a record you already hold
was included, but says nothing about what else was in the batch, so a deleted
record leaves no digest to re-hash. Each commitment therefore binds
*membership* (root and leaf count), *interval* (exactly `n` records over a
sequence span) and *continuity* (the digest of the preceding batch). The three
defend against modification, record deletion and whole-batch deletion.

**Sparse batches are legitimate.** Real ledgers have gaps — voided vouchers,
reserved ranges, numbers burned by a failed transaction. The committed count
is the ground truth, so a batch that was sparse when anchored stays valid;
what verification detects is a count that has fallen below what was committed.
Requiring density at anchoring time would have made the tool unusable against
real data.

**Verification degrades rather than fails.** Three checks run in decreasing
order of precision: witness replay names individual records; root comparison
proves that something changed without saying what; the interval check catches
deletions from the count alone. Losing off-chain material costs precision, not
soundness. The witness is itself verified against the anchored root before it
is used to accuse any record.

**Backends are interchangeable.** Only the 32-byte commitment digest is
authoritative; the body lives off-chain and is re-hashed on retrieval, so an
untrusted body store is safe to use. `tests/test_backends.py` is parametrised
over all three backends and the EVM one passes it unchanged — that, rather
than the abstract base class, is what shows the abstraction is real.

**On-chain cost is constant per batch.** What a batch commits is one
32-byte digest, and what the registry stores per batch is fixed — the digest
plus a few words of bookkeeping — regardless of how many records it covers,
so gas per anchoring transaction is constant (119.6k measured; `results/gas.csv`).
That makes batch size a genuine operating point rather than a tuning detail:
at 5 000 records per batch the committed digest amounts to 0.008 bytes and
about 24 gas per record, but a root mismatch localises tampering only to
within 5 000 records when no witness is held.

**The harness makes this research infrastructure.** Integrity research on
accounting data rests on confidential datasets and so cannot be reproduced or
compared. `synth.py` generates ledgers carrying the structural properties
detection depends on — balanced vouchers, monotonic sequences, realistic gaps —
without any real data, and `tamper.py` injects four attack classes with
ground-truth labels, so detection rates can be re-derived rather than trusted.

**Coercion is not canonicalisation.** Ingestion turns whatever a source hands
back into the types the schema declares; canonicalisation turns typed values
into bytes. Keeping the stages apart means a new data source needs only a
coercion path and cannot change a single digest. Floats and naive timestamps
are refused rather than guessed at, because both would make a digest depend on
the reader rather than on the data.

## Measured behaviour

<!-- measured:begin -->
<!-- Generated by scripts/sync_readme.py from results/. Edit the script or re-run the harness; do not edit this by hand. -->

Reproduce with `python scripts/experiments.py --runs 3`; the environment is
recorded alongside the results. Every throughput row carries its within-run
spread (across the 5 timed repeats) and its run-to-run spread (across the 3
consecutive runs in `results/throughput_runs.csv`). On the machine the shipped
numbers come from, within-run spread reaches 17% and run-to-run spread 15% --
larger than any effect of ledger size -- so re-run on your own hardware before
quoting absolute rates.

| Property | Measurement (`results/`, v0.6.13, CPython 3.12.3, 1-core x86-64 Linux VM, Intel(R) Xeon(R) Processor @ 2.10GHz; medians across 3 runs × 5 repeats) |
|---|---|
| Anchoring throughput | 42,900–45,200 records/s from 246 to 97,930 records, no trend with size; within-run spread ≤ 14%, run-to-run ≤ 10% |
| Verification throughput | 17,500–18,200 records/s with full witness replay, no trend with size; within-run spread ≤ 17%, run-to-run ≤ 15% |
| Committed per batch | one 32-byte digest, independent of batch size |
| Gas per anchoring transaction | 119,596–119,608 across batches of 10–5,000 records; first anchor on a fresh registry 136,708 |
| Inclusion proof | 14 hashes (448 B) at 16,384 records; verify in ~11 µs |
| Detection | 1,607 injected manipulations over 20 seeded runs: 100% recall on all four attack classes, 0 false positives |
<!-- measured:end -->

The detection figure is not a finding — cryptographic commitments are supposed
to catch every one of these, and anything below 100% would indicate a bug. The
informative results are the cost/localisation trade-off and the behaviour under
degraded evidence.

## Author

**Zhang Bin**  
School of Digital Intelligence Finance & Business (数智财商学院)  
Anhui Technical College of Industry and Economy (安徽工业经济职业技术学院)  
Email: zhangbin_0209@126.com

## Citation

If you use LedgerGuard in your research, please cite the software using its
Zenodo DOI: [10.5281/zenodo.22854960](https://doi.org/10.5281/zenodo.22854960).
Machine-readable citation metadata is available in [`CITATION.cff`](CITATION.cff).

## Licence

MIT.
