# Contributing

## Getting set up

```bash
pip install -e ".[dev]"
pytest
```

The core has no runtime dependencies. `web3` and `eth-tester` are needed only
for the EVM backend; the tests that use them skip themselves when they are
absent, and CI runs one job without them to keep that path honest.

## What a change needs

- **Tests.** Every behavioural change comes with a test that fails without it.
  Bugs get a regression test that reproduces the original symptom.
- **Digest stability.** Anything touching `canonical.py`, `schema.py` or a
  profile's field list changes what records hash to, which invalidates every
  existing anchor. Such a change requires a schema version bump, never a
  silent edit.
- **Never update `tests/vectors.json` to make a test pass.** Those are frozen
  outputs of the wire format. A failure there means a ledger anchored under an
  earlier release can no longer be verified, which is a breaking change even
  when every other test is green. The fix is to revert, or to bump the schema
  version so old and new records occupy disjoint digest spaces.
- **No new runtime dependencies in the core.** Optional extras are fine.

## Mutation testing

```bash
python scripts/mutate.py
```

Coverage says which lines run; it does not say whether anything would notice
if a line behaved differently. This script disables one security-relevant
decision at a time and reports whether any test fails. A surviving mutant is a
property nobody is checking — it found two, including a case where removing
the predecessor digest from the commitment preimage left all 331 tests green.

When a mutant is reported *stale*, the code it targeted has moved. Update the
fragment in `scripts/mutate.py` so the check keeps applying; do not delete it.

## Adding a profile

A profile supplies a `RecordSchema` and the domain rules that make a finding
interpretable. See `profiles/provenance.py`; it was written specifically to
check that the layers below contain nothing accounting-specific. A new profile
needs:

1. A schema with a `sequence_field`, registered in `profiles/__init__.py`.
2. Validators for the domain's own invariants.
3. A test that anchors and verifies a ledger end to end under it.

If adding a profile requires editing anything outside `profiles/`, that edit
is a leak in the abstraction and belongs in a separate commit that fixes it.

## The contract

`contracts/AnchorRegistry.sol` is compiled to a committed artifact so that
users need no Solidity toolchain. After changing the source:

```bash
python scripts/compile_contract.py --solc /path/to/solc
```

CI verifies that the committed artifact matches the source.
