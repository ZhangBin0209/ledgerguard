# Changelog

## 0.6.13

A tenth audit found one word: the README said within-run and run-to-run
spread "both reach 21%" when only one of them did. Small, but it was the
fifth release in a row in which some number quoted in the README -- a
throughput, a proof timing, a spread -- had been right when typed and
stale or imprecise by the next tag. This release removes the class of
error rather than the instance.

- **The README's "Measured behaviour" section is generated.**
  `scripts/sync_readme.py` renders it from `results/` (environment,
  throughput, gas, proof size, detection) between two marker comments;
  nothing in it is typed by hand. `--check` reports whether the README
  matches `results/`, and CI runs it on every push, so the section cannot
  be stale unless `results/` is. Rendering has its own tests. The generator
  immediately caught a second stale figure: the inclusion-proof timing had
  read "~9 µs" since 0.6.8 while the shipped measurement had moved to 11.
- `results/` regenerated on this version.

## 0.6.12

A ninth audit, with nothing to find in the code. Three words and a CI line.

- The paper called the three throughput runs "independent"; they are
  consecutive runs in one process, with warm caches. It now says so.
- The 0.6.11 entry below said `--runs 1` adds "two zero columns"; it adds
  three (`runs`, which is 1, and two spreads, which are 0). Corrected in
  place, and recorded here rather than silently.
- CI's harness smoke test passes `--runs 2`, so the cross-run aggregation
  is exercised end to end on every push and not only by its unit tests.
- `results/` regenerated on this version, as every release does, so
  `environment.json` names the release the numbers came from.

## 0.6.11

An eighth audit found nothing in the code and one thing in the paper: the
"run-to-run variation of about 20%" quoted beside the throughput figures
had no artifact behind it -- `results/` shipped one run, and the 20% came
from runs made hours apart during earlier audit rounds. The number is now
measured rather than remembered.

- `scripts/experiments.py --runs N` repeats the throughput experiment N
  times, writes the per-run medians to `results/throughput_runs.csv`, and
  reports in `throughput.csv` the median across runs together with
  `anchor_run_spread` / `verify_run_spread` ((max − min) / median of the
  per-run medians) beside the within-run spread. `aggregate_runs` is a pure
  function with its own tests. With `--runs 1` (the default and `--quick`)
  the table is unchanged apart from three added columns: `runs` (1) and
  the two run-to-run spreads (0).
- `results/` regenerated with `--runs 3`: within-run spread up to 14%,
  run-to-run spread up to 14%, both larger than any effect of ledger
  size. README, the paper and this file quote those figures and nothing
  that is not in `results/`.
- Two wording changes in the paper (Section 2.1's opening sentence, the
  throughput sentence in 3.2), no change of content.

## 0.6.10

A seventh audit, of the 0.6.9 fixes. All held; five small edges around
them.

- **Read-only views are live.** `FileBackend(read_only=True)` computed the
  intact-prefix length once, at open, so a handle opened while the store
  was torn kept serving that slice after a writer had repaired the tail
  and appended -- the appended anchors were invisible to it. The torn
  tail is now split off on every read, in both modes: reading around it
  is always sound (torn bytes were never an anchor), a read-only handle
  only reports it, and a writable handle repairs it at open and again
  before each append, so a crash in another process after open cannot
  have the next anchor written onto its debris. Two tests.
- **A missing `web3` is reported as what it is.** `MissingDependencyError`
  subclasses `AnchorError` and fell into the anchor-store branch of the
  CLI, so `ledgerguard deploy` without `web3` said "error: anchor store:
  the EVM backend requires web3". Named first now.
- A path that is a directory is refused with "is a directory, not an
  anchor store file" instead of a raw errno.
- The experiment harness records the spread across repeats
  (`anchor_spread`, `verify_spread`: (max − min) / median) beside every
  throughput figure, and defaults to five repeats, so a reader can tell
  measurement noise from a trend; on the shared virtual machine the
  shipped results come from, within-run spread is 2–12% and run-to-run
  variation about 20%, both larger than any effect of ledger size.
  `results/` regenerated on this version.
- Fig. 1's `root` arrow ran from commitment to merkle; it now runs the way
  the root flows. The tamper → canonical edge is labelled "records" --
  the ground truth goes to the scorer, not the pipeline.

## 0.6.9

A sixth audit, this one of the 0.6.8 fixes themselves. Every 0.6.8 item
held under independent probing; what it found were edges around them.

- **Verification no longer writes to the anchor store.** `verify` opened
  the file with `create=False` but `FileBackend` still truncated a torn
  final line and fsynced on open -- checking the evidence rewrote it, and
  trailing garbage vanished with a stderr note. `FileBackend` gains
  `read_only=True`: `anchor()` is refused, and a torn tail is reported as
  `torn_tail` and read around, the intact anchors before it still used.
  The CLI opens stores read-only for `verify`, prints a warning that the
  file was left untouched, and the next `anchor` repairs it exactly as
  before. Frozen as tests and as a mutant.
- **Every anchor under another schema is exit 2, not 1.** A ledger checked
  with the wrong `--profile` was reported as tampered; nothing had been
  verified. The CLI now returns 2 when all batches are schema mismatches
  (a partial mismatch is still a finding about the ledger, and stays 1).
  `docs/getting-started.md` had claimed this behaviour a release early.
- **`anchor` refuses an empty ledger** (exit 2) instead of reporting
  "anchored 0 records in 0 batches" and leaving an empty store behind --
  the same rule `ingest` already applied.
- The RPC connection seam (`_web3_for`) was unexercised by the suite; a
  test now points it at a closed port and checks for the error message
  rather than a traceback. The "anchor store: anchor store ..." message
  prefix is no longer doubled. `docs/api.md` describes `deploy`,
  `--backend`, the `FileBackend` flags and the error hierarchy.
- `results/environment.json` records the CPU model and core count;
  `platform.processor()` alone said "x86_64", which named the architecture
  and nothing about the machine. `results/` regenerated on this version.
- Fig. 1 of the manuscript now has a source in the repository
  (`scripts/architecture_figure.py`), drawn so that the harness modules sit
  outside the domain-independent core -- as the text has said since 0.6.8
  and the old figure contradicted -- and so that backends receive
  commitments rather than Merkle roots.

## 0.6.8

A fifth external audit, this one reading the SoftwareX manuscript against
the code as well as probing the code itself. One real defect, one
performance regression, and a set of claims that were true of the
integrity layer but written as if they were true of everything.

- **`verify` no longer passes for want of an anchor store.** A wrong
  `--anchors` path, a wrong working directory, or an anchor file that had
  simply been deleted each produced "0 batches verified; no discrepancies",
  exit status 0 -- and a freshly created empty store, since `FileBackend`
  touched its file on open. The one result a scheduled verification must
  never return. Three things changed: `verify_ledger` now reports every
  record as an orphan when no anchors exist, instead of treating "nothing to
  compare against" as "nothing changed"; `FileBackend(create=False)` refuses
  to create a missing store and raises `MissingAnchorStoreError`; and the CLI
  exits 2 when the store it was pointed at holds no anchors. Frozen as tests
  and as three mutants.
- **`check_interval` was quadratic in batch size.** A list-membership scan
  (`s not in in_span`) cost 0.3 s per 10,000-record batch, so verification
  throughput fell by a third between batch sizes of 100 and 10,000 -- at
  exactly the batch sizes the cost guidance recommends, and after 0.6.0 had
  claimed throughput flat in batch size. One comparison per record now; a
  wall-clock regression test at 50,000 records guards it.
- **The EVM backend is reachable from the command line.** Until now the CLI
  used only the file simulator and printed an "on-chain footprint" for a
  local JSON file; on-chain anchoring existed only through the Python API.
  `anchor` and `verify` take `--backend evm --rpc URL --contract ADDRESS
  [--account ADDRESS] [--body-store PATH]`, a `deploy` subcommand puts a
  registry on a chain, and the file backend's output says what it is.
  The CLI's EVM path is tested end to end against an in-process EVM.
- **"One word per batch" corrected.** The registry stores four storage
  words per batch (digest, packed block number and timestamp, submitter,
  and the insertion-order key), not one; the 32 bytes quoted for the
  on-chain footprint is the committed digest. Wording is corrected in the
  contract, the backend, the docs and the README, and the experiment harness
  gains a fifth experiment that measures the actual figure: 119,596–119,608
  gas per anchoring transaction across batches of 10 to 5,000 records
  (`results/gas.csv`), with a 17k premium on a fresh registry's first anchor.
  The contract itself is unchanged apart from its comments; the committed
  artifact is regenerated and its bytecode differs only in the embedded
  metadata hash.
- **The one-line verification summary surfaces interval evidence.** Without
  a witness, a five-record shortfall was summarised as "root mismatch without
  record-level attribution" while the batch detail said "5 records missing".
  Count shortfalls, surpluses, unattributed root mismatches, rejected
  witnesses and unanchored batches are now all named on the first line.
- **DATE coercion no longer truncates.** The first ten characters of a string
  were kept, so `2026-03-17junk` was accepted and `...T23:59:59+05:00` lost
  its zone. The whole string must now parse; a naive timestamp rendered by a
  DATE column is still narrowed to its date, a zoned one is refused.
- `tamper.py` said the sequence class "exchanges sequence numbers"; it never
  did. The docstring now describes what is implemented (duplicate-sequence
  insertion), what is not, and that the injector is written against the
  accounting profile.
- The null-marker rule in ingestion (`""`, `NULL`, `none`, `\N` read as null
  for nullable fields of every type, STRING included) is documented rather
  than changed: it is what makes a CSV export and a database read hash the
  same, and the alternative has a cost too.
- `results/` regenerated on this version, so `environment.json` names the
  release the numbers came from; README figures updated to match.
  `CITATION.cff` no longer describes the software as having one profile.

Probed and fine: the RFC 9162 verification walk, line by line; every
adversarial case not in the benchmark (insertion into a sparse gap, insertion
between batches, whole-batch content deletion, anchor removal, a witness
doctored to cover a modification) is detected; §3.1 of the manuscript
reproduces command for command.

## 0.6.7

A .dockerignore. The fourth audit measured the Docker build context and
found it carrying the repository history and tool caches -- nothing the
image uses, since the Dockerfile copies named paths, but a few megabytes
sent to the daemon on every build for no reason. The audit itself called
this not worth a release; it ships anyway because it was the last noted
item on the books, and a cleared ledger seems like the right state for a
tool about ledgers to rest in.


## 0.6.6

Nothing in the package's behaviour changes. A third audit read the
0.6.5 entry below against the experiments it describes and found the
attribution wrong: the 3,240 honest proofs and nineteen thousand
forged variants were resolved against a semantic oracle and an
independent root computation, while the line-for-line RFC 9162
reference verifier was compared on a separate 2,459 proof/size
combinations (and, since 0.6.5, on several hundred more in every CI
run). Nothing in the numbers was false; they were credited to the
wrong method. The entry now says what actually happened, and this one
exists so the correction lives in the history rather than in a silent
edit.

Also, CI gains a job that builds the Docker image and runs the suite
inside it. Three audit rounds never built the image -- their sandbox
had no Docker daemon -- which left the Dockerfile as the one shipped
surface nothing routinely exercised. Now the routine path exercises
it.


## 0.6.5

No behavioural change. A second external audit exercised the verifier
exhaustively -- 3,240 honest proofs and some nineteen thousand forged
variants, every one resolved correctly -- and separately cross-checked
it against a line-for-line RFC 9162 reference verifier on 2,459
proof/size combinations, the two implementations agreeing on every
case. One acceptance surprised us
before it was checked against the reference: a proof also verifies
under a neighbouring tree size that gives its index the same path
shape, because digest, index and root are all unchanged and RFC 9162's
own algorithm accepts it too. That is inherent to RFC 6962-family
proofs, not a hole; the authoritative size binding lives in the batch
commitment. This release writes the property down where it can be
found -- in the `InclusionProof` docstring -- and freezes it as a
conformance test spanning every index of every tree up to 24 leaves,
so that a future over-tightening breaks the suite instead of RFC
conformance.


## 0.6.4

Two defects in `InclusionProof.recompute_root`, both found by an external
audit that fed the verifier proofs it should never have been given. The
routine walked `index` and `last` down the tree but never checked that the
path length and `tree_size` actually described the same tree.

- **A `tree_size` smaller than the path implies hung the verifier.** The
  walk reached index 0 with siblings still unconsumed, and the promoted-node
  loop shifted `0 >> 1` forever. `verify` catches `ValueError`; it cannot
  catch non-termination. No shipped code path constructs such a proof --
  the CLI builds proofs locally from data it just hashed -- but inclusion
  proofs exist precisely to cross trust boundaries, and a verifier that can
  be hung by its input is broken in the one way a verifier must not be.
  The walk now refuses a sibling once it has reached the root.
- **A `tree_size` larger than the path implies verified successfully.** The
  same proof for a 257-leaf tree verified unchanged with `tree_size` set to
  a billion: nothing bound the field to the walk. The walk now requires
  that the path ends exactly at the root, making every field of the proof
  triple load-bearing. Both cases are frozen as tests and as mutants.

Also in this release:

- The wheel build was broken by a `force-include` that added the contract
  artifact a second time; every non-editable install failed with a
  hatchling path collision. CI never noticed because every job installed
  editable. The duplicate is gone and a `package` job now builds a real
  wheel, installs it, checks the artifact is inside, and smoke-tests the
  CLI -- the path users actually take.
- README test and mutant counts were stale; corrected, and the mutation
  count is now described as what it is: hand-curated security mutants, not
  tool-generated mutation coverage.


## 0.6.3

Two independent O(n^2) defects in `verify_ledger`, found by measuring at a
batch count the shipped benchmarks never reached. Both were invisible to unit
tests, which run at a scale far too small for quadratic cost to register.

- **`verify_ledger` re-fetched every commitment it already held.** It builds
  its batch list from one call to `backend.chain()`, then called
  `verify_batch(batch_id, ...)` per batch, which fetches the commitment
  *again* by id. On `MemoryBackend` this doubled the work; on `FileBackend`,
  where `fetch` re-reads and re-parses the whole anchor file, it turned
  verifying an N-batch ledger into an O(N^2) file scan. A 400-batch ledger
  took 1.5 seconds; a realistic 100,000-anchor store took most of a second
  just to *open*, before any verification began. `verify_ledger` now calls
  the commitment-verifying logic directly, with the fetch it already paid for.
- **Routing records to batches scanned every record for every batch.**
  Independent of backend: at 3,200 batches this alone cost 7.7 seconds on
  `MemoryBackend`, whose `fetch` is a dict lookup and was never the bottleneck.
  Records are already sorted by sequence, so each batch's slice is now found
  by binary search -- O(batches x log(records)) instead of
  O(batches x records).

Together, these meant verification throughput fell as a ledger grew, which
directly contradicts the tool's own cost advice: choosing a small batch size
for finer-grained localisation also meant more batches, which made
verification quietly quadratic. At the largest shipped benchmark (97,930
records, 980 batches), verification measured 4,793 records/s -- now 20,994.
Throughput is flat across every tested scale, from 246 to 97,930 records,
instead of falling by 4x at the high end. `results/` and the README's
verification-throughput figures are updated accordingly.

Two complexity regression tests added, following the pattern used for the
Merkle tree in 0.6.0: one counts backend reads directly rather than timing,
so it does not depend on the machine; the routing test uses a generous wall-
clock bound wide enough to tolerate normal variance while still catching a
return to quadratic behaviour. A mutation was added reintroducing the
redundant fetch, to keep the fix from silently regressing.

Investigated and unaffected: `tamper.py`'s ground truth was cross-checked
against actual digest changes across 20 seeds with zero mismatches; the
`benchmark` CLI command runs clean; the two documented on-chain cost claims
(constant storage per batch, gas independent of record count within a batch)
both hold under a real in-process EVM. A roughly 17,000-gas premium on a
contract's very first anchor, from a shared counter's storage slot going from
zero to nonzero, is real but affects neither claim and was already implicit
in `last_gas_used`.

## 0.6.2

Crash recovery for the file backend, found by probing what a power failure
actually leaves behind.

- **A torn write no longer locks out the whole anchor history.** A crash in
  the middle of an append leaves a truncated final line; the backend refused
  the entire file over it, making every intact, fsynced anchor before it
  unreadable. Those torn bytes are not an anchor -- `anchor()` fsyncs before
  returning, so a write that did not complete was never reported as anchored.
  On open, a torn final line is now removed, the intact history is kept, and
  `recovered` is set; the CLI prints a note. Truncation is also what keeps the
  *next* append safe: in append mode it would have been written onto the end
  of the garbage, corrupting a genuine anchor with a failed one's debris.
- An unreadable line anywhere other than the tail still refuses the file --
  sequential fsynced appends cannot tear a middle line, so that is damage to
  the evidence store itself, not a crash artifact. This check now runs at
  open rather than on first use.
- The batch whose write tore can be anchored again without tripping the
  duplicate check, since it was never anchored.
- `docs/chain.md` now states the contract's write model plainly: no owner, no
  access control, one registry per organisation, and what first-come
  batch-id occupancy on a shared deployment does and does not allow.

Probed and fine: duplicate sequence numbers in the observed ledger are
reported as insertions; the witness file round-trips losslessly; the
Dockerfile copies everything it references.

## 0.6.1

Mutation testing, which measures what the suite actually constrains rather
than which lines it runs. Two mutants survived all 331 tests.

- **The predecessor digest was not covered by any test.** Removing it from the
  commitment preimage left the whole suite green: `verify_chain` compares the
  `prev_digest` *field* against the predecessor's digest, so it kept working
  either way, and the frozen commitment vector used a genesis batch, where
  dropping the predecessor produces identical bytes. The code was correct
  throughout — but nothing was holding it there. Had it drifted, a batch could
  have been re-linked to a different predecessor without changing its anchored
  digest, splicing a batch out of the chain while every anchor still validated.
  Added a non-genesis commitment vector and tests for the re-linking attack.
- **`MerkleTree.append` accepted a wrong-sized digest** as far as any test
  could tell, because `leaf_hash` raises the same error later. The tree would
  have taken a malformed digest and failed when the root was computed, far from
  the record that caused it. The test now asserts the rejection happens on
  append and that nothing was stored.
- SQLite internal tables (`sqlite_master` and friends) are refused. They are
  valid identifiers, so `--table sqlite_master` was accepted and failed later
  with a coercion error about a missing column, which said nothing about the
  mistake.
- `scripts/mutate.py` added and wired into CI, so the suite's strength is
  checked on every push rather than once.

Verified and unchanged: 18/18 mutants now killed; the subtree cache added in
0.6.0 is safe under eight concurrent readers; 400 malformed CSVs and 200
hostile SQLite tables produced no unexpected exception; table-name injection
is still refused.

## 0.6.0

A performance defect that made the toolkit's own cost advice unusable.

- **Inclusion proofs were linear, not logarithmic.** The Merkle tree was never
  materialised: each proof recomputed whole subtrees from the leaves, so
  proving one leaf cost O(n) hashing and proving every leaf -- exactly what
  verifying a batch against its witness does -- cost O(n^2). Subtree roots are
  now cached by range, which the RFC 6962 split rule visits O(n) of, making the
  tree O(n) to materialise and every subsequent proof O(log n).

  The effect was not marginal. A single 5,000-record batch took 42.6 seconds to
  verify and now takes 0.42. Verification throughput had been collapsing as
  batch size grew -- 4,293 records/s at batch size 100 down to 353 at batch
  size 2,000 -- which directly contradicted the cost advice in
  `results/fig2_batch_tradeoff.png`, where large batches are recommended
  because they minimise on-chain footprint. Choosing the cheapest anchoring
  configuration had silently made verification unusable. Throughput is now flat
  in batch size.

  The frozen vectors passed unchanged throughout, confirming that roots and
  proof paths are identical; only the cost of producing them changed.

- Complexity regression tests count hash operations rather than wall-clock
  time, so they assert the asymptotics without depending on the machine. One
  covers a tree deep enough to exhaust a recursive descent, since the fix
  replaced recursion with an iterative one.
- `results/` regenerated; the verification figures in the README are updated.
- `mypy` now runs clean and in CI. It found one latent crash: `ingest` indexed
  a record by `schema.sequence_field` without checking for `None`, so a profile
  without a sequence field would have raised inside a summary line.

## 0.5.2

A second audit pass, aimed at the parts the first one did not reach:
determinism, adversarial input, concurrency, and the gap between what the
docstrings claim and what the code does.

- **Frozen wire-format vectors** (`tests/vectors.json`). Every existing test
  was *relative* — same input, same digest — and would have passed if the
  canonical encoding were replaced wholesale. Removing the domain separation
  tag, a change that silently invalidates every anchor ever written, failed
  exactly one test out of 301. It now fails nine. The vectors pin record
  digests, preimage hashes, tree roots at seven sizes, the leaf and node
  prefixes, a commitment digest, an inclusion path, and the output of both
  synthetic generators, since reported detection rates are tied to seeds.
- **CLI no longer crashes on bad input.** A missing ledger file, a missing
  database and a corrupt anchor store each produced an uncaught traceback.
  A tool that crashes on a missing file teaches its user to distrust every
  other message it prints.
- **Reading zero records is now an error.** Pointing `ingest` at the wrong
  file exited 0 and wrote an empty ledger, pushing the failure to `anchor`,
  which reported an empty batch — a message that said nothing about the actual
  mistake.

Verified and unchanged: digests are identical to 0.5.0 and 0.5.1; output is
independent of `PYTHONHASHSEED`; no preimage collisions over 2,000 generated
cases; every leaf proves at every tree size from 1 to 129; no leaf hash
coincides with any internal node hash; twenty concurrent writers leave the
file backend readable; and every behavioural claim made in a docstring was
checked against the code.

## 0.5.1

An audit pass over the packaged release. Two real defects, both found by
probing behaviour rather than by reading code.

- **Records inserted between anchored batches were invisible.** Verification
  routes records to batches by sequence span, and anything falling in no span
  was silently dropped -- so an intruder writing between two batch boundaries
  went unreported, which was the one way to walk around the scheme. Such
  records are now reported as orphans and make the ledger not intact. The
  docstring had promised this behaviour without implementing it.
- **Interval bounds were checked at encoding time, not construction.** A batch
  with a sequence beyond 2^64 built and sealed successfully, then failed when
  its digest was computed -- far from the record that caused it.

Also:

- Removed `merkle.Anchor`, which duplicated `BatchCommitment`'s role and made
  three different things in the public API called "anchor". Removed the unused
  `BatchStatus.UNVERIFIABLE` and `BatchWitness.index_of`.
- EVM contract tests asserted `pytest.raises(Exception)`, which would have
  passed on any error including a typo. They now name the exception and assert
  that the reverted state is unchanged.
- `zip(strict=True)` when replaying a witness: a silent truncation would have
  dropped records from comparison, reporting them as neither intact nor missing.
- Lint configuration added; leftover imports and a loop-variable capture in the
  provenance generator cleaned up.

## 0.5.0

Two gaps closed that would have undermined the software's central claims.

- **Second domain profile** (`provenance.instrument_event`): instrument runs
  and research data custody. It shares no field name with the accounting
  profile and exercises `DATETIME` and `BOOLEAN`, which accounting never
  touched. The whole pipeline, including the EVM backend, runs on it with no
  change below `profiles/` — which is the evidence for the domain-independence
  claim that a single profile could never provide.
- **Ingestion from real systems** (`ingest.py`): CSV and SQLite, with
  schema-driven coercion kept deliberately separate from canonicalisation so
  that a new data source cannot alter any digest. Floats and naive timestamps
  are refused rather than guessed at. `iter_sqlite` streams ledgers too large
  to hold in memory.
- Profile registry and `--profile` throughout the CLI; new `ingest` command.
- Documentation set under `docs/`, three runnable examples, Dockerfile,
  CONTRIBUTING and issue templates.

Fixes, all found by exercising the new paths:

- The `eth-tester` dependency was pinned `>=0.12`, which resolves to nothing:
  the project only ever publishes pre-releases. A clean `pip install -e ".[dev]"`
  failed outright — the single most common reason a software submission cannot
  be evaluated.

- SQLite reads now order by `CAST(seq AS INTEGER)`. A `TEXT` sequence column
  sorted 1, 10, 100, 2, and a batch built from that read would have committed
  to an interval with wrong bounds.
- `SyntheticLedger.sequences` read `line_seq` by name, quietly tying the
  generator to the accounting profile.
- The verifier now checks that an anchor's schema matches the one it was given.
  Previously a profile mismatch reported every record as modified — true, and
  useless.
- The CLI exits cleanly on a closed pipe and reports user errors without a
  traceback.

## 0.4.0

- `AnchorRegistry` Solidity contract: append-only, one storage word per batch
- `EVMBackend` implementing the same interface as the simulators; it passes
  `tests/test_backends.py` unchanged, which is the test of the abstraction
- In-process EVM via `eth-tester`, so contract execution is exercised offline
  and in CI without deploying a node
- Compiled artifact shipped, so no Solidity toolchain is needed to run the
  software; `scripts/compile_contract.py --check` verifies it against source
- `scripts/experiments.py`: four reproducible experiments producing CSV and
  figures, with the environment recorded alongside
- Transaction references normalised to `0x`-prefixed hex (web3 7 dropped the
  prefix from `HexBytes.hex()`)

## 0.3.0

- Verifier producing per-record forensic findings backed by inclusion proofs
- `BatchWitness`: off-chain leaf digests, validated against the anchored root
  before use, enabling attribution while keeping soundness without it
- Synthetic ledger generator with seeded reproducibility and realistic gaps
- Tamper injector covering four attack classes with ground-truth labels
- Command-line interface: `generate`, `anchor`, `verify`, `benchmark`
- Duplicate observed sequence numbers are now reported as insertions rather
  than silently displacing the genuine record

## 0.2.0

- Batch commitments binding membership, interval and continuity
- Hash chain over batches, detecting removal of a whole batch
- Pluggable `ChainBackend` with in-memory and append-only file simulators
- Sparse batches accepted: the committed count, not density, is ground truth

## 0.1.0

- Generic record schema and canonical encoding
- RFC 6962 Merkle tree with inclusion proofs
- Accounting journal-entry profile
