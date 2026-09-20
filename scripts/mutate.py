#!/usr/bin/env python3
"""Mutation testing: measure what the test suite actually constrains.

Coverage says which lines run. It does not say whether anything would notice
if a line behaved differently. This script changes one security-relevant
decision at a time and reports whether any test fails.

A surviving mutant is a property nobody is checking. Two were found this way:

*   Removing the predecessor digest from the commitment preimage left the
    whole suite green. `verify_chain` compares the *field*, so it kept
    working, and the frozen commitment vector used a genesis batch, where
    dropping the predecessor produces identical bytes. An adversary could
    have re-linked a batch to a different predecessor without changing its
    anchored digest, splicing a batch out of the chain.
*   Removing the digest-size check on `MerkleTree.append` also survived,
    because `leaf_hash` raises the same error later. The tree would have
    accepted a malformed digest and failed at root time, far from the cause.

Usage:
    python scripts/mutate.py            # run every mutant
    python scripts/mutate.py --list     # show them without running
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "ledgerguard"

#: (module, exact source to replace, replacement, description).
#: Each mutation disables one decision that the design depends on. The source
#: fragments are exact so that a refactor makes a mutant *invalid* -- reported
#: loudly -- rather than silently inapplicable.
MUTANTS: list[tuple[str, str, str, str]] = [
    ("verifier.py", "if anchored in digests:", "if anchored in digests or True:",
     "treat every observed record as intact"),
    ("verifier.py", "and not self.orphan_sequences", "and True",
     "ignore records outside every anchored span"),
    ("verifier.py",
     "if (commitment.schema_id, commitment.schema_version) != (",
     "if False and (commitment.schema_id, commitment.schema_version) != (",
     "skip the schema-identity check"),
    ("verifier.py", "if not witness.verify_against(commitment):",
     "if False and not witness.verify_against(commitment):",
     "accept a witness that does not rebuild the anchored root"),
    ("commitment.py", "if current.prev_digest != expected:", "if False:",
     "skip the chain-link check"),
    ("commitment.py", "if self.tree_size != self.interval.count:", "if False:",
     "allow tree_size to disagree with the interval count"),
    ("commitment.py", "if seq < self._sequences[-1]:", "if False:",
     "allow records to be added out of sequence order"),
    ("commitment.py", "                lp(self.prev_digest),",
     "                lp(GENESIS_DIGEST),",
     "drop the predecessor from the commitment preimage"),
    ("merkle.py", '_LEAF_PREFIX = b"\\x00"', '_LEAF_PREFIX = b"\\x01"',
     "collapse leaf/node domain separation"),
    ("merkle.py",
     """        if len(digest) != DIGEST_SIZE:
            raise ValueError(
                f"expected a {DIGEST_SIZE}-byte digest, got {len(digest)}"
            )
        self._leaves.append(bytes(digest))""",
     "        self._leaves.append(bytes(digest))",
     "accept a wrong-sized digest on append"),
    ("merkle.py", "if last == 0:", "if False:",
     "accept a proof path longer than its tree_size implies"),
    ("merkle.py", "if last != 0:", "if False:",
     "accept a proof path shorter than its tree_size implies"),
    ("backends.py", "if commitment.batch_id in self._index:", "if False:",
     "allow a batch id to be re-anchored"),
    ("backends.py", "if recomputed != record.digest:", "if False:",
     "skip revalidating a retrieved body against its digest"),
    ("canonical.py", "if spec.strip:", "if False:",
     "stop stripping surrounding whitespace"),
    ("canonical.py", "if scaled != minor:", "if False:",
     "silently round amounts with excess precision"),
    ("ingest.py", 'query += f\' ORDER BY CAST("{order}" AS INTEGER)\'',
     'query += f\' ORDER BY "{order}"\'',
     "order a TEXT sequence column lexicographically"),
    ("ingest.py", "if parsed.tzinfo is None:", "if False:",
     "accept naive timestamps without a declared zone"),
    ("profiles/accounting.py", "if debit != credit:", "if False:",
     "skip the voucher balance check"),
    ("profiles/provenance.py", "if _instant(later) < _instant(earlier):",
     "if False:", "skip chronological ordering within a run"),
    ("verifier.py",
     "            reports.append(\n                self._verify_commitment(",
     "            reports.append(\n                self.verify_batch(",
     "reintroduce the O(n^2) redundant fetch inside verify_ledger"),
    ("verifier.py", "orphans = sorted(set(seqs) - routed)",
     "orphans = sorted(set(seqs) - routed) if commitments else []",
     "verify clean against an empty anchor store (fail open)"),
    ("cli.py", "    if not anchors:\n", "    if False:\n",
     "let the CLI verify a ledger against a store holding no anchors"),
    ("backends.py", "            if not create or read_only:\n", "            if False:\n",
     "create an empty anchor store when opened for verification"),
    ("backends.py", "        if not read_only:\n            self._recover_torn_tail()",
     "        if True:\n            self._recover_torn_tail()",
     "let a read-only open rewrite the anchor store"),
    ("cli.py", "    if not records:\n        # Anchoring nothing", "    if False:\n        # Anchoring nothing",
     "anchor an empty ledger successfully"),
]


def run() -> int:
    survived, killed, invalid = [], [], []

    for module, find, replace, description in MUTANTS:
        path = SRC / module
        original = path.read_text()
        if find not in original:
            invalid.append(description)
            continue

        path.write_text(original.replace(find, replace, 1))
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-x", "--no-header",
                 "-p", "no:cacheprovider"],
                cwd=ROOT, capture_output=True, text=True, timeout=600,
            )
            (killed if result.returncode != 0 else survived).append(description)
        except subprocess.TimeoutExpired:
            killed.append(f"{description} (timed out)")
        finally:
            path.write_text(original)

        print(".", end="", flush=True)

    total = len(MUTANTS) - len(invalid)
    print(f"\n\nkilled {len(killed)}/{total}")

    for description in survived:
        print(f"  SURVIVED: {description}")
    for description in invalid:
        print(f"  STALE (source no longer matches): {description}")

    if survived:
        print("\nA surviving mutant is a property no test constrains.")
    if invalid:
        print("\nA stale mutant means the code moved; update scripts/mutate.py "
              "so the check keeps applying.")

    return 1 if (survived or invalid) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true",
                        help="print the mutants without running them")
    args = parser.parse_args()

    if args.list:
        for module, _, _, description in MUTANTS:
            print(f"  {module:<28} {description}")
        return 0
    return run()


if __name__ == "__main__":
    sys.exit(main())
