// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LedgerGuard anchor registry
/// @notice Stores one 32-byte commitment digest per batch, permanently.
///
/// The contract is deliberately minimal. Everything that can be checked
/// off-chain is checked off-chain: the Merkle root, the interval claim and the
/// chain link all live inside the digest, and re-deriving them on-chain would
/// cost gas without adding any guarantee. What the chain provides that no
/// off-chain store can is the one thing implemented here — a record that
/// cannot be rewritten by whoever controls the ledger database.
///
/// Two invariants carry the whole design:
///
/// 1. **Append-only.** `anchor` reverts on a batch id that already exists.
///    An anchor that can be overwritten is not evidence, so the contract
///    offers no update or delete path at all — not even to the owner, since an
///    owner-only override would still be an override.
///
/// 2. **Constant cost.** What a batch commits is one 32-byte digest, and
///    what the registry stores per batch is fixed -- the digest plus block
///    number, timestamp and submitter (three storage words), and the key in
///    the insertion-order index (one more) -- regardless of how many records
///    the batch covers. Gas per anchoring transaction is therefore constant
///    (about 120k on `paris`; the first anchor pays roughly 17k more to take
///    the counter slot from zero), so anchoring cost scales with batch count
///    rather than ledger size. This is what makes the batch-size parameter a
///    genuine cost/granularity trade-off rather than a tuning detail.
///
///    The metadata words are a convenience, not a guarantee: block number and
///    timestamp are also in the transaction receipt and the `Anchored` event.
///    A registry that stored the digest alone would be cheaper; it is not
///    what this version ships.
contract AnchorRegistry {
    struct Anchor {
        bytes32 digest;
        uint64 blockNumber;
        uint64 timestamp;
        address submitter;
    }

    /// @dev Keyed by keccak256 of the batch id, so ids of any length cost the
    /// same to store and to look up.
    mapping(bytes32 => Anchor) private _anchors;

    /// @dev Insertion order, so an auditor can walk the whole registry
    /// without knowing the batch ids in advance.
    bytes32[] private _keys;

    event Anchored(
        bytes32 indexed batchKey,
        string batchId,
        bytes32 digest,
        uint256 index
    );

    error AlreadyAnchored(string batchId);
    error EmptyBatchId();
    error ZeroDigest();
    error UnknownBatch(string batchId);
    error IndexOutOfRange(uint256 index, uint256 length);

    /// @notice Record a commitment digest for `batchId`.
    /// @dev Reverts if the batch id has been anchored before.
    function anchor(string calldata batchId, bytes32 digest) external {
        if (bytes(batchId).length == 0) revert EmptyBatchId();
        // A zero digest is almost certainly an uninitialised variable rather
        // than a real commitment, and admitting it would make `isAnchored`
        // ambiguous against the mapping's default value.
        if (digest == bytes32(0)) revert ZeroDigest();

        bytes32 key = keccak256(bytes(batchId));
        if (_anchors[key].digest != bytes32(0)) revert AlreadyAnchored(batchId);

        _anchors[key] = Anchor({
            digest: digest,
            blockNumber: uint64(block.number),
            timestamp: uint64(block.timestamp),
            submitter: msg.sender
        });
        _keys.push(key);

        emit Anchored(key, batchId, digest, _keys.length - 1);
    }

    /// @notice The digest anchored for `batchId`, and when.
    function get(string calldata batchId)
        external
        view
        returns (bytes32 digest, uint64 blockNumber, uint64 timestamp, address submitter)
    {
        Anchor storage a = _anchors[keccak256(bytes(batchId))];
        if (a.digest == bytes32(0)) revert UnknownBatch(batchId);
        return (a.digest, a.blockNumber, a.timestamp, a.submitter);
    }

    /// @notice Whether `batchId` has been anchored.
    function isAnchored(string calldata batchId) external view returns (bool) {
        return _anchors[keccak256(bytes(batchId))].digest != bytes32(0);
    }

    /// @notice Number of anchors recorded.
    function count() external view returns (uint256) {
        return _keys.length;
    }

    /// @notice The anchor at `index` in insertion order.
    function at(uint256 index)
        external
        view
        returns (bytes32 batchKey, bytes32 digest, uint64 blockNumber, uint64 timestamp)
    {
        if (index >= _keys.length) revert IndexOutOfRange(index, _keys.length);
        bytes32 key = _keys[index];
        Anchor storage a = _anchors[key];
        return (key, a.digest, a.blockNumber, a.timestamp);
    }
}
