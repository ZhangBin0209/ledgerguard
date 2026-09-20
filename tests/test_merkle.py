"""Merkle tree tests.

The proof machinery has to be exercised at every tree size, not just the
convenient powers of two -- odd sizes are where Merkle implementations
usually go wrong.
"""

from __future__ import annotations

import hashlib

import pytest

from ledgerguard import MerkleTree, leaf_hash, node_hash
from ledgerguard.merkle import InclusionProof


def d(n: int) -> bytes:
    """A distinct 32-byte digest for leaf ``n``."""
    return hashlib.sha256(f"record-{n}".encode()).digest()


def tree(n: int) -> MerkleTree:
    return MerkleTree(d(i) for i in range(n))


# --------------------------------------------------------------------------
# Structure
# --------------------------------------------------------------------------


def test_empty_tree_root_matches_rfc6962():
    assert MerkleTree().root == hashlib.sha256(b"").digest()


def test_single_leaf_root_is_the_leaf_hash():
    assert tree(1).root == leaf_hash(d(0))


def test_two_leaf_root_is_the_node_hash():
    assert tree(2).root == node_hash(leaf_hash(d(0)), leaf_hash(d(1)))


def test_leaf_and_node_domains_are_separated():
    """A leaf hash must never be constructible as an internal node hash.

    This is the second-preimage defence: distinct prefixes mean a crafted
    record digest cannot masquerade as a subtree root.
    """
    payload = d(0)
    assert leaf_hash(payload) != hashlib.sha256(payload).digest()
    assert leaf_hash(payload) != node_hash(payload[:16], payload[16:])


def test_root_depends_on_leaf_order():
    """The tree commits to a sequence, not a set."""
    assert MerkleTree([d(0), d(1)]).root != MerkleTree([d(1), d(0)]).root


def test_appending_changes_the_root():
    t = tree(5)
    before = t.root
    t.append(d(5))
    assert t.root != before


def test_rejects_wrong_sized_digest_at_append_time():
    """The rejection must happen on append, not later when the root is taken.

    `leaf_hash` performs the same check, so a test that only asserts "some
    ValueError is raised" passes either way. Accepting the digest and failing
    at root time would report the error far from the record that caused it,
    and would leave a tree in an unusable state in between.
    """
    t = MerkleTree([d(0), d(1)])
    with pytest.raises(ValueError, match="32-byte"):
        t.append(b"too short")
    assert len(t) == 2, "a rejected digest must not have been stored"
    assert t.root == MerkleTree([d(0), d(1)]).root


# --------------------------------------------------------------------------
# Inclusion proofs
# --------------------------------------------------------------------------


@pytest.mark.parametrize("n", range(1, 33))
def test_every_leaf_proves_at_every_tree_size(n):
    """Exhaustive over sizes 1..32, including all the awkward odd ones."""
    t = tree(n)
    root = t.root
    for i in range(n):
        assert t.prove(i).verify(root), f"leaf {i} of {n} failed"


@pytest.mark.parametrize("n", [1, 2, 3, 7, 8, 100, 1000])
def test_proof_size_is_logarithmic(n):
    t = tree(n)
    assert len(t.prove(0).path) <= max(1, n - 1).bit_length()


def test_proof_fails_against_a_different_root():
    assert not tree(8).prove(3).verify(tree(9).root)


def test_tampered_digest_fails_verification():
    """The core detection case: a record's content was altered."""
    t = tree(8)
    good = t.prove(3)
    tampered = InclusionProof(
        index=good.index,
        tree_size=good.tree_size,
        digest=d(999),  # what a modified record would now hash to
        path=good.path,
    )
    assert good.verify(t.root)
    assert not tampered.verify(t.root)


def test_relocated_leaf_fails_verification():
    """Claiming a record sat at a different position must not verify."""
    t = tree(8)
    good = t.prove(3)
    moved = InclusionProof(
        index=4, tree_size=good.tree_size, digest=good.digest, path=good.path
    )
    assert not moved.verify(t.root)


def test_truncated_tree_fails_against_original_root():
    """An adversary who drops the tail of a batch changes the root.

    The leaf count that pins how many records the root covers lives in the
    commitment, not here; see test_commitment.py.
    """
    full = tree(9)
    truncated = tree(8)
    assert len(full) == 9 and len(truncated) == 8
    assert truncated.root != full.root
    assert not truncated.prove(0).verify(full.root)


def test_tampered_path_fails_verification():
    t = tree(8)
    good = t.prove(3)
    corrupted = InclusionProof(
        index=good.index,
        tree_size=good.tree_size,
        digest=good.digest,
        path=(d(777),) + good.path[1:],
    )
    assert not corrupted.verify(t.root)


def test_out_of_range_index_does_not_verify():
    t = tree(4)
    bogus = InclusionProof(index=9, tree_size=4, digest=d(0), path=())
    assert not bogus.verify(t.root)


def test_prove_digest_finds_the_leaf():
    t = tree(6)
    assert t.prove_digest(d(4)).index == 4
    with pytest.raises(KeyError):
        t.prove_digest(d(99))


def test_prove_rejects_out_of_range_index():
    with pytest.raises(IndexError):
        tree(4).prove(4)


# --------------------------------------------------------------------------
# Determinism
# --------------------------------------------------------------------------


def test_root_is_a_32_byte_digest():
    t = tree(7)
    assert len(t.root) == 32
    assert t.root_hex == t.root.hex()


def test_trees_are_reproducible():
    """Two independent builds over the same digests give the same root."""
    assert tree(50).root == tree(50).root
    assert tree(50).root_hex == tree(50).root_hex


# --------------------------------------------------------------------------
# Complexity
#
# These assert asymptotic behaviour, not wall-clock times, so they do not
# depend on the machine. They exist because the naive recursive formulation
# recomputes whole subtrees per proof: correct, and quadratic to prove a whole
# batch, which made verification of a 5000-record batch take 40 seconds.
# --------------------------------------------------------------------------


def _count_hashes(fn):
    """Number of SHA-256 constructions performed while running ``fn``."""
    import hashlib as _h

    calls = 0
    original = _h.sha256

    def counting(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    _h.sha256 = counting
    try:
        fn()
    finally:
        _h.sha256 = original
    return calls


def test_proof_generation_is_logarithmic_not_linear():
    """A single proof from a materialised tree must not rehash the batch."""
    small, large = tree(256), tree(4096)
    small.root, large.root  # materialise both  # noqa: B018

    cost_small = _count_hashes(lambda: small.prove(128))
    cost_large = _count_hashes(lambda: large.prove(2048))

    # Sixteen times the leaves, at most a handful more hashes.
    assert cost_large <= cost_small + 32, (
        f"proving in a 4096-leaf tree cost {cost_large} hashes against "
        f"{cost_small} in a 256-leaf tree; the tree is being recomputed"
    )


def test_proving_every_leaf_is_subquadratic():
    """Verifying a batch against its witness proves every leaf in it."""
    n = 1024
    t = tree(n)
    t.root  # noqa: B018

    cost = _count_hashes(lambda: [t.prove(i) for i in range(n)])
    # A quadratic implementation costs on the order of n^2 = 1_048_576 hashes.
    assert cost < 8 * n, f"{cost} hashes to prove {n} leaves"


def test_building_the_tree_hashes_each_node_once():
    n = 1024
    t = tree(n)
    cost = _count_hashes(lambda: t.root)
    # n leaf hashes plus n-1 internal nodes.
    assert cost <= 2 * n, f"{cost} hashes to build a {n}-leaf tree"


def test_cache_is_dropped_when_a_leaf_is_appended():
    """A stale cache would return the previous root, which is a correctness
    failure rather than a performance one."""
    t = tree(8)
    before = t.root
    t.append(d(8))
    assert t.root != before
    assert t.root == MerkleTree([d(i) for i in range(9)]).root
    assert t.prove(3).verify(t.root)


def test_deep_tree_does_not_exhaust_the_recursion_limit():
    """The descent is iterative; a recursive one would cap out on tall trees."""
    import sys

    original = sys.getrecursionlimit()
    sys.setrecursionlimit(120)
    try:
        t = tree(20000)
        assert len(t.root) == 32
        assert t.prove(9999).verify(t.root)
    finally:
        sys.setrecursionlimit(original)


def test_proof_with_understated_tree_size_is_rejected_not_hung():
    """A ``tree_size`` smaller than the path implies must fail, and fail fast.

    In 0.6.3 this exact input hung the verifier: the walk reached index 0
    with siblings left, and the promoted-node loop shifted 0 >> 1 forever.
    Proof objects are the one artefact designed to cross a trust boundary,
    so malformed ones must be rejected, never looped on.
    """
    import dataclasses

    t = tree(257)
    honest = t.prove(0)
    forged = dataclasses.replace(honest, tree_size=256)
    assert not forged.verify(t.root)
    with pytest.raises(ValueError):
        forged.recompute_root()


def test_proof_with_overstated_tree_size_is_rejected():
    """A ``tree_size`` larger than the path implies must also fail.

    Before the walk checked that the path actually reaches the root,
    ``tree_size`` was a free-floating field: a proof for a 257-leaf tree
    verified unchanged with ``tree_size`` set to a billion.  The field is
    part of what the proof asserts, so it must be bound by verification.
    """
    import dataclasses

    t = tree(257)
    honest = t.prove(0)
    assert honest.verify(t.root)
    forged = dataclasses.replace(honest, tree_size=10**9)
    assert not forged.verify(t.root)
    with pytest.raises(ValueError):
        forged.recompute_root()


def test_tampered_proof_fields_never_verify():
    """Each field of the proof triple is load-bearing."""
    import dataclasses

    t = tree(257)
    for index in (0, 1, 127, 128, 255, 256):
        honest = t.prove(index)
        assert honest.verify(t.root)
        assert not dataclasses.replace(honest, digest=d(9999)).verify(t.root)
        assert not dataclasses.replace(honest, index=(index + 1) % 257).verify(t.root)


def test_verification_matches_the_rfc_9162_reference_algorithm():
    """Freeze RFC 9162 conformance, including its shape-equivalence edge.

    The reference algorithm below is a line-for-line transcription of
    RFC 9162 section 2.1.3.2.  For every index of every tree up to 24
    leaves, and for claimed tree sizes one below, at, and one above the
    true size, our verifier must agree with the reference exactly.

    This deliberately freezes a subtle acceptance: a proof also verifies
    under a neighbouring tree size that gives the index the same path
    shape (sizes 3 and 4 for index 0, say), because digest, index and
    root are unchanged and the reference algorithm accepts it too.  A
    future "fix" that rejects those would break RFC conformance; this
    test exists so that it fails loudly instead.  The authoritative size
    binding lives in the batch commitment, which is tested elsewhere.
    """
    import dataclasses

    def rfc9162_root(digest, index, tree_size, path):
        if not 0 <= index < tree_size:
            return None
        fn, sn = index, tree_size - 1
        r = leaf_hash(digest)
        for p in path:
            if sn == 0:
                return None
            if fn & 1 or fn == sn:
                r = node_hash(p, r)
                if not fn & 1:
                    while True:
                        fn >>= 1
                        sn >>= 1
                        if fn & 1 or fn == 0:
                            break
            else:
                r = node_hash(r, p)
            fn >>= 1
            sn >>= 1
        return r if sn == 0 else None

    for n in range(1, 25):
        t = tree(n)
        for i in range(n):
            proof = t.prove(i)
            for claimed in (n - 1, n, n + 1):
                if claimed < 1:
                    continue
                candidate = dataclasses.replace(proof, tree_size=claimed)
                expected = rfc9162_root(
                    candidate.digest, candidate.index,
                    candidate.tree_size, candidate.path,
                ) == t.root
                assert candidate.verify(t.root) == expected, (n, i, claimed)
