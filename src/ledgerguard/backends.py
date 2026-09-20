"""Pluggable anchoring backends.

Everything above this module is chain-agnostic.  A backend is responsible for
one thing: storing a 32-byte commitment digest somewhere that the ledger
operator cannot retroactively rewrite, and handing back a reference that lets
an auditor find it again.

Two properties shape the interface.  First, **only the digest is
authoritative**.  Real chains charge per byte, so the commitment body lives
off-chain and is re-hashed on retrieval; a backend that silently returned a
body which did not match its digest would defeat the entire scheme, so
:meth:`ChainBackend.fetch` checks that itself.  Second, **anchoring is
append-only**.  Re-anchoring a batch id is refused rather than treated as an
update, because an anchor that can be overwritten is not evidence.

The simulators here are not a convenience for development.  A reviewer will
not deploy a chain to evaluate this software, and an experiment whose results
depend on a live network is not reproducible; :class:`MemoryBackend` and
:class:`FileBackend` make every result in the paper re-runnable offline.  An
EVM backend implementing the same three methods is the only chain-specific
code in the project.
"""

from __future__ import annotations

import json
import os
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

from .commitment import BatchCommitment
from .merkle import DIGEST_SIZE


class AnchorError(RuntimeError):
    """A backend refused or failed an anchoring operation."""


class DuplicateAnchorError(AnchorError):
    """A batch id has already been anchored."""


class CorruptAnchorError(AnchorError):
    """A stored commitment body does not match its anchored digest."""


class MissingAnchorStoreError(AnchorError):
    """A backend was opened for reading but its store does not exist.

    Raised instead of silently creating an empty store: a verifier pointed at
    the wrong path -- or at a path whose anchor file has been deleted -- must
    fail, not report that nothing has changed.
    """


@dataclass(frozen=True)
class AnchorRecord:
    """One anchored commitment as retrieved from a backend.

    Attributes:
        commitment: The off-chain body.
        digest: The authoritative on-chain value.
        backend: Name of the backend that holds it.
        reference: Backend-specific locator -- a sequence number for the
            simulators, a transaction hash for a real chain.
        anchored_at: Time the backend recorded the anchor.  For a real chain
            this is the block timestamp, which is why it is not part of the
            commitment preimage.
    """

    commitment: BatchCommitment
    digest: bytes
    backend: str
    reference: str
    anchored_at: datetime

    @property
    def batch_id(self) -> str:
        return self.commitment.batch_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest.hex(),
            "backend": self.backend,
            "reference": self.reference,
            "anchored_at": self.anchored_at.isoformat(),
            "commitment": self.commitment.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnchorRecord:
        return cls(
            commitment=BatchCommitment.from_dict(data["commitment"]),
            digest=bytes.fromhex(data["digest"]),
            backend=data["backend"],
            reference=data["reference"],
            anchored_at=datetime.fromisoformat(data["anchored_at"]),
        )


class ChainBackend(ABC):
    """Interface every anchoring backend implements.

    A backend must be append-only and must verify on retrieval that a stored
    commitment body still hashes to its anchored digest.
    """

    name: str = "abstract"

    @abstractmethod
    def anchor(self, commitment: BatchCommitment) -> AnchorRecord:
        """Record a commitment digest.

        Raises:
            DuplicateAnchorError: the batch id is already anchored.
        """

    @abstractmethod
    def fetch(self, batch_id: str) -> AnchorRecord | None:
        """Retrieve an anchor, or ``None`` if the batch id is unknown.

        Raises:
            CorruptAnchorError: the stored body does not match its digest.
        """

    @abstractmethod
    def __iter__(self) -> Iterator[AnchorRecord]:
        """Iterate anchors in the order they were recorded."""

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def latest(self) -> AnchorRecord | None:
        """The most recently anchored record, if any."""
        last = None
        for record in self:
            last = record
        return last

    def next_prev_digest(self) -> bytes:
        """Predecessor digest for the next batch in the chain."""
        from .commitment import GENESIS_DIGEST

        latest = self.latest()
        return latest.digest if latest else GENESIS_DIGEST

    def chain(self) -> Sequence[BatchCommitment]:
        """All anchored commitments, in order, for chain verification."""
        return [record.commitment for record in self]

    def _validate(self, record: AnchorRecord) -> AnchorRecord:
        """Re-hash a retrieved body against its anchored digest."""
        if len(record.digest) != DIGEST_SIZE:
            raise CorruptAnchorError(
                f"anchor {record.batch_id!r}: digest is not {DIGEST_SIZE} bytes"
            )
        recomputed = record.commitment.digest()
        if recomputed != record.digest:
            raise CorruptAnchorError(
                f"anchor {record.batch_id!r}: stored commitment hashes to "
                f"{recomputed.hex()[:16]}... but {record.digest.hex()[:16]}... "
                "was anchored"
            )
        return record


class MemoryBackend(ChainBackend):
    """In-process backend.  Fast, ephemeral, used by the test suite."""

    name = "memory"

    def __init__(self) -> None:
        self._records: list[AnchorRecord] = []
        self._index: dict[str, AnchorRecord] = {}

    def anchor(self, commitment: BatchCommitment) -> AnchorRecord:
        if commitment.batch_id in self._index:
            raise DuplicateAnchorError(
                f"batch {commitment.batch_id!r} is already anchored; "
                "anchors are append-only"
            )
        record = AnchorRecord(
            commitment=commitment,
            digest=commitment.digest(),
            backend=self.name,
            reference=str(len(self._records)),
            anchored_at=datetime.now(timezone.utc),
        )
        self._records.append(record)
        self._index[commitment.batch_id] = record
        return record

    def fetch(self, batch_id: str) -> AnchorRecord | None:
        record = self._index.get(batch_id)
        return self._validate(record) if record else None

    def __iter__(self) -> Iterator[AnchorRecord]:
        return iter(list(self._records))


class FileBackend(ChainBackend):
    """Append-only JSON Lines backend.

    Each anchor is one line.  The file is opened in append mode and written
    with an fsync, so an anchor survives a crash between the write and the
    next operation -- an anchor that can be lost on a power failure would let
    an operator claim a batch had never been anchored.

    **Crash recovery.** A crash in the middle of an append leaves a torn
    final line. Those bytes are not an anchor: :meth:`anchor` fsyncs before it
    returns, so a write that did not complete was never reported as anchored
    to anyone. On open, a torn *final* line is therefore removed and the
    intact history before it is kept, with :attr:`recovered` set so tools can
    say so. Truncating is also what keeps the *next* append safe -- in append
    mode it would otherwise be written onto the end of the garbage, corrupting
    a genuine anchor.

    An unreadable line anywhere *other* than the tail cannot be produced by a
    crash, because appends are sequential and each is fsynced before the next
    begins. That is corruption or tampering of the evidence store itself, and
    the backend refuses the file rather than guessing which parts to trust.
    """

    name = "file"

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        create: bool = True,
        read_only: bool = False,
    ) -> None:
        """Open an anchor store.

        Args:
            path: The JSON Lines file.
            create: Create the file (and parent directories) if absent. Pass
                ``False`` when opening a store to *verify against*: a store
                that does not exist is then an error rather than an empty,
                freshly created file that every ledger verifies clean
                against (found by external audit of 0.6.7).
            read_only: Never write to the file. :meth:`anchor` is refused,
                and a torn final line is *reported* (:attr:`torn_tail`) and
                read around rather than truncated away. Verification opens
                the store this way: checking evidence must not alter it
                (found by external audit of 0.6.8, which caught ``verify``
                rewriting the anchor file).

        Raises:
            MissingAnchorStoreError: ``create`` is false and the file is absent.
        """
        self.path = Path(path)
        self.read_only = read_only
        if self.path.is_dir():
            raise AnchorError(
                f"{self.path} is a directory, not an anchor store file"
            )
        if not self.path.exists():
            if not create or read_only:
                raise MissingAnchorStoreError(
                    f"{self.path} does not exist; either nothing has been "
                    "anchored there or the path is wrong"
                )
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch()
        #: True when this open removed a torn final line left by a crash.
        self.recovered: bool = False
        #: True when the most recent read found a torn final line and read
        #: around it. Re-evaluated on every read, so a handle opened while
        #: the store was torn sees the repair -- and any anchors appended
        #: after it -- rather than a slice frozen at open (found by external
        #: audit of 0.6.9). A writable handle repairs the tail at open and
        #: before each append, so it normally reads False there.
        self.torn_tail: bool = False
        if not read_only:
            self._recover_torn_tail()
        # Validate the whole store now rather than on first use. A corrupt
        # evidence file should refuse to open, not open cleanly and then fail
        # inside whatever operation happens to read it first.
        self._read_all()

    @staticmethod
    def _split_torn_tail(raw: bytes) -> tuple[bytes, bytes]:
        """Split a store into its intact prefix and a torn final fragment.

        The fragment is empty when the file ends cleanly, and also when the
        last line is a complete JSON document that merely lost its newline
        -- that is an anchor, not debris.
        """
        if not raw or raw.endswith(b"\n"):
            return raw, b""
        head, _, tail = raw.rpartition(b"\n")
        try:
            json.loads(tail.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return (head + b"\n" if head else b""), tail
        return raw, b""

    def _recover_torn_tail(self) -> None:
        """Repair the file in place (writable opens only).

        Also called before every append, so a crash that tears the tail
        *after* this handle was opened cannot have the next anchor written
        onto the end of its debris.
        """
        raw = self.path.read_bytes()
        if not raw:
            return
        keep, fragment = self._split_torn_tail(raw)
        if not fragment and not keep.endswith(b"\n"):
            # A complete anchor missing only its newline: normalise it so the
            # next append starts on a fresh line instead of being written
            # onto the end of this one.
            keep = keep + b"\n"
        if keep != raw:
            with self.path.open("wb") as handle:
                handle.write(keep)
                handle.flush()
                os.fsync(handle.fileno())
            self.recovered = True

    def _read_all(self) -> list[AnchorRecord]:
        # Read the intact prefix as it stands *now*. A torn tail is never an
        # anchor, so reading around it is sound in either mode; a writable
        # handle repairs it at open and again before each append, a
        # read-only one only reports it. Damage anywhere else still refuses
        # the file below.
        raw, fragment = self._split_torn_tail(self.path.read_bytes())
        self.torn_tail = bool(fragment)
        records = []
        for lineno, line_bytes in enumerate(raw.split(b"\n"), start=1):
            line = line_bytes.strip()
            if not line:
                continue
            try:
                records.append(AnchorRecord.from_dict(json.loads(line.decode("utf-8"))))
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError) as exc:
                raise CorruptAnchorError(
                    f"{self.path}:{lineno} is not a readable anchor: {exc}"
                ) from exc
        return records

    def anchor(self, commitment: BatchCommitment) -> AnchorRecord:
        if self.read_only:
            raise AnchorError(
                f"{self.path} was opened read-only; anchoring is refused"
            )
        self._recover_torn_tail()
        existing = {r.batch_id for r in self._read_all()}
        if commitment.batch_id in existing:
            raise DuplicateAnchorError(
                f"batch {commitment.batch_id!r} is already anchored in {self.path}"
            )
        record = AnchorRecord(
            commitment=commitment,
            digest=commitment.digest(),
            backend=self.name,
            reference=f"{self.path.name}:{len(existing)}",
            anchored_at=datetime.now(timezone.utc),
        )
        # Binary append with an explicit LF: text mode would translate "\n"
        # to "\r\n" on Windows, making the on-disk format OS-dependent (and
        # breaking the append-only tail contract the readers rely on). Writing
        # bytes keeps the store byte-identical across platforms.
        with self.path.open("ab") as handle:
            handle.write(json.dumps(record.to_dict(), sort_keys=True).encode("utf-8") + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def fetch(self, batch_id: str) -> AnchorRecord | None:
        for record in self._read_all():
            if record.batch_id == batch_id:
                return self._validate(record)
        return None

    def __iter__(self) -> Iterator[AnchorRecord]:
        return iter(self._read_all())


def temporary_file_backend() -> FileBackend:
    """A :class:`FileBackend` in a throwaway directory, for examples."""
    return FileBackend(Path(tempfile.mkdtemp(prefix="ledgerguard-")) / "anchors.jsonl")
