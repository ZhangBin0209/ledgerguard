"""Backend tests.

Both simulators are held to the same contract, so the suite is parametrised
over them. An EVM backend added later must pass this same file unchanged --
that is the point of the abstraction.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from decimal import Decimal

import pytest

from ledgerguard import (
    GENESIS_DIGEST,
    BatchBuilder,
    CorruptAnchorError,
    DuplicateAnchorError,
    FileBackend,
    MemoryBackend,
    verify_chain,
)
from ledgerguard.backends import AnchorError, AnchorRecord
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1


def ln(seq):
    return {
        "line_seq": seq, "voucher_no": f"JV-{seq}", "line_no": 1,
        "period": "2026-03", "posting_date": date(2026, 3, 17),
        "account_code": "1001", "debit": Decimal("100.00"),
        "credit": Decimal("0.00"), "currency": "CNY", "description": None,
        "preparer": "chen.wei", "document_ref": None,
    }


def build(seqs, batch_id="B1", prev=GENESIS_DIGEST):
    b = BatchBuilder(JOURNAL_ENTRY_V1, batch_id, prev)
    b.extend(ln(s) for s in seqs)
    return b.seal()


def _evm_backend(tmp_path):
    """An EVM backend on an in-process EVM, skipped if web3 is absent."""
    web3 = pytest.importorskip("web3", reason="the EVM backend requires web3")
    pytest.importorskip("eth_tester", reason="in-process EVM requires eth-tester")
    from ledgerguard.evm import EVMBackend

    return EVMBackend.in_memory_chain(
        body_store=FileBackend(tmp_path / "bodies.jsonl")
    )


@pytest.fixture(params=["memory", "file", "evm"])
def backend(request, tmp_path):
    """Every backend is held to the same contract.

    The EVM backend is the point of this parametrisation: it is the only
    chain-specific code in the project, and it passes this file unchanged.
    """
    if request.param == "memory":
        return MemoryBackend()
    if request.param == "file":
        return FileBackend(tmp_path / "anchors.jsonl")
    return _evm_backend(tmp_path)


# -- contract shared by every backend --------------------------------------

def test_anchor_then_fetch(backend):
    commitment = build([1, 2, 3]).commitment
    record = backend.anchor(commitment)

    assert record.digest == commitment.digest()
    assert record.batch_id == "B1"
    assert record.backend == backend.name

    fetched = backend.fetch("B1")
    assert fetched is not None
    assert fetched.digest == commitment.digest()
    assert fetched.commitment == commitment


def test_fetch_unknown_batch_returns_none(backend):
    assert backend.fetch("nope") is None


def test_anchors_are_append_only(backend):
    commitment = build([1, 2, 3]).commitment
    backend.anchor(commitment)
    with pytest.raises(DuplicateAnchorError):
        backend.anchor(commitment)


def test_reanchoring_a_batch_id_with_new_content_is_refused(backend):
    """The attack this blocks: re-anchor the same id over doctored records."""
    backend.anchor(build([1, 2, 3], "B1").commitment)
    with pytest.raises(DuplicateAnchorError):
        backend.anchor(build([1, 2, 9], "B1").commitment)


def test_iteration_preserves_anchoring_order(backend):
    for i in range(4):
        backend.anchor(build([i * 10 + j for j in range(3)], f"B{i}").commitment)
    assert [r.batch_id for r in backend] == ["B0", "B1", "B2", "B3"]
    assert len(backend) == 4


def test_latest_and_next_prev_digest(backend):
    assert backend.latest() is None
    assert backend.next_prev_digest() == GENESIS_DIGEST

    first = backend.anchor(build([1, 2], "B0").commitment)
    assert backend.latest().batch_id == "B0"
    assert backend.next_prev_digest() == first.digest


def test_backend_drives_a_verifiable_chain(backend):
    """Anchoring a run of batches produces a chain that verifies end to end."""
    for i in range(5):
        prev = backend.next_prev_digest()
        backend.anchor(build([i * 10 + j for j in range(3)], f"B{i}", prev).commitment)
    verify_chain(backend.chain())


def test_record_round_trips_through_dict(backend):
    from ledgerguard.backends import AnchorRecord

    original = backend.anchor(build([1, 2, 3]).commitment)
    restored = AnchorRecord.from_dict(original.to_dict())
    assert restored.digest == original.digest
    assert restored.commitment == original.commitment


# -- file backend specifics -------------------------------------------------

def test_file_backend_persists_across_instances(tmp_path):
    path = tmp_path / "anchors.jsonl"
    FileBackend(path).anchor(build([1, 2, 3]).commitment)

    reopened = FileBackend(path)
    assert len(reopened) == 1
    assert reopened.fetch("B1") is not None


def test_file_backend_creates_missing_directories(tmp_path):
    backend = FileBackend(tmp_path / "deep" / "nested" / "anchors.jsonl")
    backend.anchor(build([1]).commitment)
    assert backend.path.exists()


def test_tampered_body_is_caught_on_fetch(tmp_path):
    """The core backend guarantee: a rewritten body no longer matches its digest.

    An operator with write access to the off-chain store edits the committed
    count. The anchored digest is unchanged, so the mismatch is detectable.
    """
    path = tmp_path / "anchors.jsonl"
    backend = FileBackend(path)
    backend.anchor(build([1, 2, 3]).commitment)

    entry = json.loads(path.read_text().strip())
    entry["commitment"]["count"] = 2
    entry["commitment"]["last_seq"] = 2
    entry["commitment"]["tree_size"] = 2
    path.write_text(json.dumps(entry) + "\n")

    with pytest.raises(CorruptAnchorError, match="anchored"):
        FileBackend(path).fetch("B1")


def test_tampered_root_is_caught_on_fetch(tmp_path):
    path = tmp_path / "anchors.jsonl"
    FileBackend(path).anchor(build([1, 2, 3]).commitment)

    entry = json.loads(path.read_text().strip())
    entry["commitment"]["root"] = "ab" * 32
    path.write_text(json.dumps(entry) + "\n")

    with pytest.raises(CorruptAnchorError):
        FileBackend(path).fetch("B1")


def test_unreadable_line_is_reported_with_location(tmp_path):
    path = tmp_path / "anchors.jsonl"
    path.write_text("{not json\n")
    with pytest.raises(CorruptAnchorError, match="anchors.jsonl:1"):
        FileBackend(path).fetch("B1")


def test_blank_lines_are_ignored(tmp_path):
    path = tmp_path / "anchors.jsonl"
    FileBackend(path).anchor(build([1, 2]).commitment)
    with path.open("a") as fh:
        fh.write("\n\n")
    assert len(FileBackend(path)) == 1


def test_backends_agree_on_the_digest(tmp_path):
    """The commitment digest is backend-independent, as it must be."""
    commitment = build([1, 2, 3]).commitment
    mem = MemoryBackend().anchor(commitment)
    fil = FileBackend(tmp_path / "a.jsonl").anchor(commitment)
    assert mem.digest == fil.digest == commitment.digest()


# --------------------------------------------------------------------------
# Crash recovery
#
# anchor() fsyncs before it returns, so a torn final line is a write that was
# never reported as anchored -- not evidence. Refusing the whole file over
# one, as the backend did before 0.6.2, meant a single crash locked out the
# entire intact history. Corruption anywhere else is a different matter:
# appends are sequential, so a bad line mid-file cannot be a crash artifact.
# --------------------------------------------------------------------------


def _anchored_file(tmp_path, n=3):
    path = tmp_path / "anchors.jsonl"
    backend = FileBackend(path)
    for i in range(n):
        builder = BatchBuilder(JOURNAL_ENTRY_V1, f"B{i}", backend.next_prev_digest())
        builder.extend(ln(s) for s in (i * 10 + 1, i * 10 + 2))
        backend.anchor(builder.seal().commitment)
    return path, backend


def test_torn_final_line_is_recovered_not_fatal(tmp_path):
    path, _ = _anchored_file(tmp_path)
    path.write_bytes(path.read_bytes() + b'{"batch_id": "B3", "root": "ab')

    reopened = FileBackend(path)
    assert reopened.recovered
    assert len(reopened) == 3
    assert [r.batch_id for r in reopened] == ["B0", "B1", "B2"]


def test_recovery_truncates_so_the_next_append_is_clean(tmp_path):
    """In append mode a new anchor would land on the end of the garbage,
    corrupting a genuine anchor with a failed one's debris."""
    path, _ = _anchored_file(tmp_path)
    path.write_bytes(path.read_bytes() + b'{"torn')

    backend = FileBackend(path)
    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B3", backend.next_prev_digest())
    builder.extend([ln(31)])
    backend.anchor(builder.seal().commitment)

    fresh = FileBackend(path)
    assert not fresh.recovered
    assert [r.batch_id for r in fresh] == ["B0", "B1", "B2", "B3"]


def test_the_batch_whose_write_tore_can_be_anchored_again(tmp_path):
    """The torn write never returned success, so the batch was never anchored
    and anchoring it again must not be treated as a duplicate."""
    path, backend = _anchored_file(tmp_path)
    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B3", backend.next_prev_digest())
    builder.extend([ln(31)])
    sealed = builder.seal()

    line = json.dumps(AnchorRecord(
        commitment=sealed.commitment, digest=sealed.commitment.digest(),
        backend="file", reference="x",
        anchored_at=datetime.now(timezone.utc)).to_dict())
    path.write_bytes(path.read_bytes() + line[: len(line) // 2].encode())

    recovered = FileBackend(path)
    assert recovered.recovered
    recovered.anchor(sealed.commitment)  # must not raise DuplicateAnchorError
    assert recovered.fetch("B3") is not None


def test_complete_final_line_missing_newline_is_kept(tmp_path):
    """Losing only the newline must not cost the anchor it terminates."""
    path, _ = _anchored_file(tmp_path)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))

    backend = FileBackend(path)
    assert backend.recovered  # the file was normalised
    assert len(backend) == 3

    builder = BatchBuilder(JOURNAL_ENTRY_V1, "B3", backend.next_prev_digest())
    builder.extend([ln(31)])
    backend.anchor(builder.seal().commitment)
    assert [r.batch_id for r in FileBackend(path)] == ["B0", "B1", "B2", "B3"]


def test_corruption_before_the_tail_still_refuses(tmp_path):
    """Sequential fsynced appends cannot tear a middle line; that is damage
    to the evidence store itself, and guessing which parts to trust is not
    this backend's call to make."""
    path, _ = _anchored_file(tmp_path)
    lines = path.read_bytes().splitlines(keepends=True)
    lines[1] = b'{"mangled": \n'
    path.write_bytes(b"".join(lines))

    with pytest.raises(CorruptAnchorError, match=":2"):
        FileBackend(path)


def test_a_file_containing_only_a_torn_line_recovers_to_empty(tmp_path):
    path = tmp_path / "anchors.jsonl"
    path.write_bytes(b'{"torn')
    backend = FileBackend(path)
    assert backend.recovered and len(backend) == 0


def test_clean_files_do_not_set_the_recovered_flag(tmp_path):
    path, _ = _anchored_file(tmp_path)
    assert not FileBackend(path).recovered


# -- 0.6.8 ------------------------------------------------------------------


def test_file_backend_can_refuse_to_create_a_missing_store(tmp_path):
    from ledgerguard import MissingAnchorStoreError

    path = tmp_path / "nowhere" / "anchors.jsonl"
    with pytest.raises(MissingAnchorStoreError):
        FileBackend(path, create=False)
    assert not path.exists()
    assert not path.parent.exists()


def test_file_backend_read_only_open_still_reads_an_existing_store(tmp_path):
    path = tmp_path / "anchors.jsonl"
    FileBackend(path).anchor(build([1, 2]).commitment)
    assert len(FileBackend(path, create=False)) == 1


# -- 0.6.9: read-only opens never write --------------------------------------


def _torn(tmp_path):
    path, _ = _anchored_file(tmp_path)
    path.write_bytes(path.read_bytes() + b'{"torn write from a crash')
    return path


def test_read_only_open_reads_around_a_torn_tail_without_writing(tmp_path):
    """Regression: verification opened the store, truncated the torn line and
    fsynced -- checking the evidence rewrote it (found by external audit of
    0.6.8)."""
    path = _torn(tmp_path)
    before = path.read_bytes()

    backend = FileBackend(path, read_only=True)

    assert path.read_bytes() == before
    assert backend.torn_tail and not backend.recovered
    assert [r.batch_id for r in backend] == ["B0", "B1", "B2"]
    assert backend.fetch("B2") is not None


def test_read_only_open_refuses_to_anchor(tmp_path):
    path, _ = _anchored_file(tmp_path)
    backend = FileBackend(path, read_only=True)
    with pytest.raises(AnchorError, match="read-only"):
        backend.anchor(build([99], "B9").commitment)


def test_read_only_open_leaves_a_missing_newline_alone(tmp_path):
    path, _ = _anchored_file(tmp_path)
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    before = path.read_bytes()
    backend = FileBackend(path, read_only=True)
    assert path.read_bytes() == before
    assert not backend.torn_tail and not backend.recovered
    assert len(backend) == 3


def test_read_only_open_of_a_missing_store_is_an_error(tmp_path):
    from ledgerguard import MissingAnchorStoreError

    with pytest.raises(MissingAnchorStoreError):
        FileBackend(tmp_path / "absent.jsonl", read_only=True)


def test_writable_open_after_read_only_still_repairs(tmp_path):
    path = _torn(tmp_path)
    FileBackend(path, read_only=True)          # looks, does not touch
    repaired = FileBackend(path)               # the next writer repairs it
    assert repaired.recovered
    assert path.read_bytes().endswith(b"}\n")


# -- 0.6.10: read-only views are live, writers survive a tail torn after open


def test_read_only_view_sees_a_repair_and_appends_made_after_open(tmp_path):
    """Regression: the intact-prefix length was cached at open, so a handle
    opened while the store was torn kept reporting the old slice after a
    writer had repaired the tail and appended (found by external audit of
    0.6.9)."""
    path = _torn(tmp_path)
    view = FileBackend(path, read_only=True)
    assert len(view) == 3 and view.torn_tail

    writer = FileBackend(path)                     # repairs ...
    writer.anchor(build([99], "B9", writer.next_prev_digest()).commitment)  # ... and appends

    assert len(view) == 4
    assert not view.torn_tail
    assert view.fetch("B9") is not None


def test_writer_repairs_a_tail_torn_after_it_was_opened(tmp_path):
    path, _ = _anchored_file(tmp_path)
    writer = FileBackend(path)
    path.write_bytes(path.read_bytes() + b'{"torn by another process')

    writer.anchor(build([99], "B9", writer.next_prev_digest()).commitment)

    assert b"torn by" not in path.read_bytes()
    assert [r.batch_id for r in FileBackend(path, read_only=True)] == [
        "B0", "B1", "B2", "B9"]


def test_a_directory_is_not_an_anchor_store(tmp_path):
    with pytest.raises(AnchorError, match="directory"):
        FileBackend(tmp_path)
