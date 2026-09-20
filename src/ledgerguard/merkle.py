"""Merkle tree over record digests, with inclusion proofs.

The construction follows RFC 6962 (Certificate Transparency) rather than the
Bitcoin variant.  Two properties motivate that choice:

*   **Distinct leaf and internal prefixes.**  Leaves are hashed as
    ``H(0x00 || d)`` and internal nodes as ``H(0x01 || left || right)``.
    Without the distinction, an attacker who controls a leaf value could
    submit a crafted "record" whose digest is itself a valid internal node,
    and then present a subtree as if it were a single record -- the classic
    second-preimage attack on unprefixed Merkle trees.

*   **No duplication of the final odd node.**  Bitcoin duplicates the last
    node when a level has an odd count, which makes certain distinct leaf
    sequences produce identical roots.  RFC 6962 splits instead at the
    largest power of two below ``n``, which is collision-free with respect to
    the leaf sequence.

The tree commits to the leaf *sequence*, not to a set: order matters, and
the leaf count is carried alongside the root in :class:`MerkleTree.anchor`.
Committing to the count is what stops a truncated tree from validating
against the original root.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"

DIGEST_SIZE = 32


def _sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for chunk in chunks:
        h.update(chunk)
    return h.digest()


def leaf_hash(digest: bytes) -> bytes:
    """Hash of a leaf holding ``digest`` (a 32-byte record digest)."""
    if len(digest) != DIGEST_SIZE:
        raise ValueError(f"expected a {DIGEST_SIZE}-byte digest, got {len(digest)}")
    return _sha256(_LEAF_PREFIX, digest)


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash of an internal node with the given children."""
    return _sha256(_NODE_PREFIX, left, right)


def _largest_power_of_two_below(n: int) -> int:
    """Largest ``k`` with ``k < n`` and ``k`` a power of two.  ``n >= 2``."""
    return 1 << (n - 1).bit_length() - 1


#: Hash of the empty tree, per RFC 6962.
EMPTY_ROOT = hashlib.sha256(b"").digest()


class _Nodes:
    """Subtree roots, computed once and reused.

    The recursive definition of the tree is naturally expressed over slices of
    the leaf sequence, but evaluating it that way recomputes whole subtrees on
    every call: building one inclusion proof costs O(n) hashing rather than
    O(log n), and building a proof for every leaf -- which is exactly what
    verifying a batch against its witness does -- costs O(n^2).

    The split rule visits only O(n) distinct ``(offset, length)`` ranges, so
    caching subtree roots by range makes the tree cost O(n) to materialise and
    every subsequent proof O(log n). The cache is keyed by range rather than by
    node index because RFC 6962 trees are not complete: for a leaf count that
    is not a power of two, levels have no uniform width.
    """

    __slots__ = ("_cache", "_leaves")

    def __init__(self, leaves: Sequence[bytes]) -> None:
        self._leaves = leaves
        self._cache: dict[tuple[int, int], bytes] = {}

    def root(self, offset: int = 0, length: int | None = None) -> bytes:
        if length is None:
            length = len(self._leaves)
        if length == 0:
            return EMPTY_ROOT
        if length == 1:
            return leaf_hash(self._leaves[offset])

        key = (offset, length)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        # Iterative descent down the left spine, then combine on the way back
        # up, so a tall tree cannot exhaust the recursion limit.
        stack = []
        while length > 1:
            k = _largest_power_of_two_below(length)
            stack.append((offset, length, k))
            offset, length = offset, k

        node = leaf_hash(self._leaves[offset])
        while stack:
            base, span, k = stack.pop()
            node = node_hash(node, self.root(base + k, span - k))
            self._cache[(base, span)] = node
        return node

    def path(self, index: int) -> list[bytes]:
        """Sibling hashes for ``index``, ordered from the leaf upward."""
        siblings: list[bytes] = []
        offset, length = 0, len(self._leaves)
        while length > 1:
            k = _largest_power_of_two_below(length)
            if index - offset < k:
                siblings.append(self.root(offset + k, length - k))
                length = k
            else:
                siblings.append(self.root(offset, k))
                offset, length = offset + k, length - k
        siblings.reverse()
        return siblings


@dataclass(frozen=True)
class InclusionProof:
    """Evidence that one record digest sits at a known position in a tree.

    Attributes:
        index: Zero-based position of the leaf.
        tree_size: Number of leaves in the tree the proof was cut from.
        digest: The record digest being proven.
        path: Sibling hashes, ordered from the leaf upward.

    A note on what ``tree_size`` proves.  Verification binds the field only
    as far as RFC 9162 semantics can: a proof also verifies under any other
    tree size that gives this index the same path shape and reproduces the
    same root (for example, sizes 3 and 4 for index 0).  This is inherent
    to RFC 6962-family proofs, not a defect -- such a relabelling proves
    nothing new, since digest, index and root are all unchanged.  The
    authoritative tree size lives in the anchored batch commitment, which
    binds it into the committed digest and checks it against the interval
    count.  Treat the field here as the size the proof was cut at, fully
    authenticated only jointly with that commitment.
    """

    index: int
    tree_size: int
    digest: bytes
    path: tuple[bytes, ...]

    def recompute_root(self) -> bytes:
        """Recompute the root implied by this proof.

        The caller compares the result against the anchored root; a mismatch
        means the record, its position, or the tree is not what was anchored.
        """
        if not 0 <= self.index < self.tree_size:
            raise ValueError("index out of range for tree_size")

        node = leaf_hash(self.digest)
        index, last = self.index, self.tree_size - 1
        for sibling in self.path:
            if last == 0:
                # The walk already reached the root; any further sibling is
                # not part of a tree of the claimed size.  Without this guard
                # a proof whose ``tree_size`` understates the path length sent
                # the promoted-node loop below spinning on index 0 forever --
                # a hang, in the one routine built to consume adversarial
                # input (found by external audit of 0.6.3).
                raise ValueError("proof path longer than tree_size implies")
            if index % 2 == 1 or index == last:
                node = node_hash(sibling, node)
                # Advance to the parent's coordinates, skipping the levels
                # that a promoted odd node passes through untouched.  The
                # ``index != 0`` bound cannot fire while the length guard
                # above holds -- it is the second line of defence that turns
                # a future regression there into a wrong root rather than a
                # hang, since 0 >> 1 is 0 and this loop would never exit.
                while index != 0 and index % 2 == 0:
                    index >>= 1
                    last >>= 1
            else:
                node = node_hash(node, sibling)
            index >>= 1
            last >>= 1
        if last != 0:
            # The path ran out before the walk reached the root: the proof is
            # structurally too short for the claimed ``tree_size``.  Accepting
            # it would let ``tree_size`` be an unchecked, free-floating field.
            raise ValueError("proof path shorter than tree_size implies")
        return node

    def verify(self, root: bytes) -> bool:
        """Whether this proof reconstructs ``root``."""
        try:
            return self.recompute_root() == root
        except ValueError:
            return False


class MerkleTree:
    """A Merkle tree over an ordered sequence of record digests."""

    def __init__(self, digests: Sequence[bytes] = ()) -> None:
        self._leaves: list[bytes] = []
        self._nodes: _Nodes | None = None
        for d in digests:
            self.append(d)

    def _materialise(self) -> _Nodes:
        """The cached node set, rebuilt only after the leaves change."""
        if self._nodes is None:
            self._nodes = _Nodes(self._leaves)
        return self._nodes

    def append(self, digest: bytes) -> int:
        """Append a record digest.  Returns its leaf index."""
        if len(digest) != DIGEST_SIZE:
            raise ValueError(
                f"expected a {DIGEST_SIZE}-byte digest, got {len(digest)}"
            )
        self._leaves.append(bytes(digest))
        # Appending changes every subtree root on the right spine, so the
        # cache is dropped rather than patched. Batches are built once and
        # then proved many times, which is the case worth optimising.
        self._nodes = None
        return len(self._leaves) - 1

    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def leaves(self) -> tuple[bytes, ...]:
        return tuple(self._leaves)

    @property
    def root(self) -> bytes:
        return self._materialise().root()

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    def prove(self, index: int) -> InclusionProof:
        """Build an inclusion proof for the leaf at ``index``."""
        if not 0 <= index < len(self._leaves):
            raise IndexError(f"leaf index {index} out of range")
        return InclusionProof(
            index=index,
            tree_size=len(self._leaves),
            digest=self._leaves[index],
            path=tuple(self._materialise().path(index)),
        )

    def prove_digest(self, digest: bytes) -> InclusionProof:
        """Inclusion proof for the first leaf equal to ``digest``."""
        try:
            index = self._leaves.index(bytes(digest))
        except ValueError:
            raise KeyError("digest is not present in this tree") from None
        return self.prove(index)
