"""LedgerGuard: tamper evidence for append-only structured records."""

from .backends import (
    AnchorError,
    AnchorRecord,
    ChainBackend,
    CorruptAnchorError,
    DuplicateAnchorError,
    FileBackend,
    MemoryBackend,
    MissingAnchorStoreError,
)
from .canonical import canonical_preimage, record_digest, record_digest_hex
from .commitment import (
    GENESIS_DIGEST,
    Batch,
    BatchBuilder,
    BatchCommitment,
    BatchWitness,
    Interval,
    IntervalFinding,
    check_interval,
    verify_chain,
)
from .ingest import (
    IngestError,
    coerce_record,
    coerce_value,
    read_csv,
    read_sqlite,
)
from .merkle import InclusionProof, MerkleTree, leaf_hash, node_hash
from .profiles import get_profile, profile_names
from .schema import FieldSpec, FieldType, RecordSchema
from .verifier import (
    BatchReport,
    BatchStatus,
    LedgerReport,
    RecordFinding,
    Verdict,
    Verifier,
    format_report,
)

__version__ = "0.6.13"

__all__ = [
    # schema
    "FieldSpec",
    "FieldType",
    "RecordSchema",
    # canonicalisation
    "canonical_preimage",
    "record_digest",
    "record_digest_hex",
    # merkle
    "InclusionProof",
    "MerkleTree",
    "leaf_hash",
    "node_hash",
    # commitments
    "GENESIS_DIGEST",
    "Batch",
    "BatchBuilder",
    "BatchCommitment",
    "Interval",
    "IntervalFinding",
    "check_interval",
    "verify_chain",
    # backends
    "AnchorError",
    "AnchorRecord",
    "ChainBackend",
    "CorruptAnchorError",
    "DuplicateAnchorError",
    "FileBackend",
    "MemoryBackend",
    "MissingAnchorStoreError",
    # commitments (witness)
    "BatchWitness",
    # verification
    "BatchReport",
    "BatchStatus",
    "LedgerReport",
    "RecordFinding",
    "Verdict",
    "Verifier",
    "format_report",
    # ingestion
    "IngestError",
    "coerce_record",
    "coerce_value",
    "read_csv",
    "read_sqlite",
    # profiles
    "get_profile",
    "profile_names",
]
