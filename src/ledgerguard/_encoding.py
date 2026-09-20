"""Low-level encoding primitives shared by the record and commitment layers.

Both layers build a byte string that gets hashed, and both need the same
guarantee: no two distinct structures may produce the same bytes.  Every
variable-length element is therefore length-prefixed, and each layer prefixes
its whole preimage with a distinct domain tag so that a record encoding can
never be reinterpreted as a commitment encoding, or vice versa.
"""

from __future__ import annotations

UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def u32(n: int) -> bytes:
    """Encode a length or count as four big-endian bytes."""
    if not 0 <= n <= UINT32_MAX:
        raise ValueError(f"value {n} out of range for a 32-bit field")
    return n.to_bytes(4, "big")


def u64(n: int) -> bytes:
    """Encode a sequence number as eight big-endian bytes.

    Signed sequence values are rejected: a ledger sequence counts upward from
    a known origin, and admitting negatives would let two different intervals
    encode identically after wrap-around.
    """
    if not 0 <= n <= UINT64_MAX:
        raise ValueError(f"value {n} out of range for a 64-bit field")
    return n.to_bytes(8, "big")


def lp(payload: bytes) -> bytes:
    """Length-prefix a byte string."""
    return u32(len(payload)) + payload


def lp_text(text: str) -> bytes:
    """Length-prefix a UTF-8 encoded string."""
    return lp(text.encode("utf-8"))
