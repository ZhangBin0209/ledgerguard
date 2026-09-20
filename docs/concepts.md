# Concepts

## The problem

Journal entries live in tables that privileged users can edit directly. The
application's audit log is governed by the same access control as the data it
records, so whoever can rewrite the ledger can usually rewrite the log. An
auditor receiving an export has no cryptographic basis for believing it is
what was originally posted.

## Canonicalisation

The same record exported from two systems is rarely byte-identical: field
order differs, an amount appears as `100`, `100.0` or `"100.00"`, a date
arrives as text in one export and a `date` object in another, nulls are `None`
here and `""` there, text differs in Unicode normalisation form.

The canonical encoding fixes each degree of freedom, and length-prefixes every
element so no two distinct records collide by concatenation. Floats and excess
precision are refused rather than rounded: silently accepting them would make
a digest depend on how a value happened to round-trip.

## Three claims

A Merkle root proves a record you already hold was included. It says nothing
about what else was in the batch, so a deleted record leaves nothing to
re-hash. Each commitment therefore binds:

| Claim | Content | Defends against |
|---|---|---|
| Membership | Merkle root and leaf count | Modification, reordering |
| Interval | Exactly *n* records over a sequence span | Deleting a record |
| Continuity | Digest of the preceding batch | Deleting a whole batch |

Only the 32-byte digest of all three goes on chain.

## Sparse batches

Real ledgers have gaps: voided vouchers, reserved ranges, numbers burned by a
failed transaction. The committed *count* is ground truth, not density. A
batch that was sparse when anchored stays valid; what verification detects is
a count that has fallen below what was committed. Requiring density would have
made the tool unusable against real data.

In a dense batch the missing sequence numbers can be named. In a sparse one
they cannot — a gap is indistinguishable from a deletion by sequence number
alone — so the shortfall is reported and the specific records are identified
by replaying inclusion proofs against the witness.

## Degraded verification

Three checks run in decreasing order of precision and increasing robustness:

1. **Witness replay** names individual records. Needs the witness.
2. **Root comparison** proves something changed, without saying what.
3. **Interval check** catches deletions from the count alone.

The witness is verified against the anchored root before it is used to accuse
any record, so an untrusted or doctored witness cannot manufacture a finding.

## The wire format is frozen

`tests/vectors.json` holds the exact digests, preimage hashes, tree roots and
commitment values this implementation produces. Every other test in the suite
is relative — same input, same digest — and would pass if the encoding were
replaced wholesale.

That matters because a digest is a promise: a ledger anchored last year must
still verify against today's code. A silent encoding change breaks every
existing anchor, and the breakage surfaces only as an inexplicable mass
verification failure long after the commit that caused it.

If the encoding must change, bump the schema version. Old and new records then
occupy disjoint digest spaces and existing anchors stay verifiable under their
own version.
