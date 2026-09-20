"""CLI integration tests: the four subcommands, end to end on real files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ledgerguard import synth, tamper
from ledgerguard.cli import main, read_ledger, write_ledger


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


def anchored_workspace(ws: Path, vouchers=60, seed=1, batch_size=25) -> Path:
    assert main(["generate", "--vouchers", str(vouchers), "--seed", str(seed),
                 "-o", "ledger.json"]) == 0
    assert main(["anchor", "ledger.json", "--batch-size", str(batch_size)]) == 0
    return ws / "ledger.json"


def test_generate_writes_a_readable_ledger(workspace):
    assert main(["generate", "--vouchers", "20", "--seed", "1", "-o", "l.json"]) == 0
    records = read_ledger(workspace / "l.json")
    assert len(records) >= 40
    assert all("line_seq" in r for r in records)


def test_generate_is_reproducible_through_the_cli(workspace):
    main(["generate", "--vouchers", "20", "--seed", "7", "-o", "a.json"])
    main(["generate", "--vouchers", "20", "--seed", "7", "-o", "b.json"])
    assert (workspace / "a.json").read_text() == (workspace / "b.json").read_text()


def test_anchor_writes_anchors_and_witnesses(workspace):
    anchored_workspace(workspace)
    assert (workspace / "anchors.jsonl").exists()
    assert (workspace / "witnesses.json").exists()
    witnesses = json.loads((workspace / "witnesses.json").read_text())
    assert witnesses and all("digests" in w for w in witnesses.values())


def test_verify_returns_zero_on_a_clean_ledger(workspace):
    anchored_workspace(workspace)
    assert main(["verify", "ledger.json"]) == 0


def test_verify_returns_nonzero_on_a_tampered_ledger(workspace):
    """The exit code matters: this is what makes the tool usable in CI."""
    anchored_workspace(workspace)
    records = read_ledger(workspace / "ledger.json")
    result = tamper.inject(records, seed=2, amount=1, deletion=1)
    write_ledger(workspace / "tampered.json", result.records)

    assert main(["verify", "tampered.json"]) == 1


def test_verify_json_output_is_parseable(workspace, capsys):
    anchored_workspace(workspace)
    records = read_ledger(workspace / "ledger.json")
    result = tamper.inject(records, seed=3, amount=1)
    write_ledger(workspace / "t.json", result.records)

    capsys.readouterr()  # discard the setup commands' output
    main(["verify", "t.json", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert report["intact"] is False
    assert report["totals"]["modified"] == 1


def test_verify_without_witnesses_still_detects(workspace):
    anchored_workspace(workspace)
    records = read_ledger(workspace / "ledger.json")
    result = tamper.inject(records, seed=4, deletion=1)
    write_ledger(workspace / "t.json", result.records)

    assert main(["verify", "t.json", "--witnesses", "missing.json"]) == 1


def test_benchmark_reports_full_recall(workspace, capsys):
    assert main(["benchmark", "--vouchers", "150", "--seed", "5",
                 "--amount", "5", "--deletion", "5",
                 "--period", "5", "--sequence", "5"]) == 0
    out = capsys.readouterr().out
    assert "100.0%" in out
    assert "false positives: 0" in out


def test_amounts_survive_the_json_round_trip(workspace):
    """Amounts must not pass through a float in serialisation."""
    from decimal import Decimal
    ledger = synth.generate(vouchers=40, seed=6)
    write_ledger(workspace / "l.json", ledger.records)
    restored = read_ledger(workspace / "l.json")

    assert all(isinstance(r["debit"], Decimal) for r in restored)
    assert [r["debit"] for r in restored] == [r["debit"] for r in ledger]


def test_digests_survive_the_json_round_trip(workspace):
    from ledgerguard import record_digest
    from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1

    ledger = synth.generate(vouchers=40, seed=8)
    write_ledger(workspace / "l.json", ledger.records)
    restored = read_ledger(workspace / "l.json")

    assert [record_digest(r, JOURNAL_ENTRY_V1) for r in restored] == \
           [record_digest(r, JOURNAL_ENTRY_V1) for r in ledger]


def test_unknown_profile_exits_cleanly_without_a_traceback(workspace, capsys):
    with pytest.raises(SystemExit):
        main(["--profile", "nonexistent", "generate"])


def test_ingest_error_reports_without_a_traceback(workspace, capsys):
    (workspace / "bad.csv").write_text("line_seq,voucher_no\n1,JV-1\n", encoding="utf-8")
    assert main(["ingest", "bad.csv", "-o", "out.json"]) == 2
    assert "error:" in capsys.readouterr().err


def test_second_profile_round_trips_through_the_cli(workspace):
    assert main(["--profile", "provenance", "generate",
                 "--vouchers", "20", "--seed", "1", "-o", "runs.json"]) == 0
    assert main(["--profile", "provenance", "anchor", "runs.json",
                 "--batch-size", "50"]) == 0
    assert main(["--profile", "provenance", "verify", "runs.json"]) == 0


def test_verifying_with_the_wrong_profile_is_reported_clearly(workspace, capsys):
    main(["--profile", "provenance", "generate", "--vouchers", "20",
          "--seed", "1", "-o", "runs.json"])
    main(["--profile", "provenance", "anchor", "runs.json"])
    capsys.readouterr()

    assert main(["--profile", "accounting", "verify", "runs.json"]) == 2
    assert "error:" in capsys.readouterr().err


def test_ingest_from_sqlite_end_to_end(workspace):
    import sqlite3

    from ledgerguard.ingest import write_sqlite
    from ledgerguard.profiles import get_profile

    ledger = synth.generate(vouchers=40, seed=2)
    connection = sqlite3.connect(workspace / "erp.db")
    write_sqlite(connection, ledger.records, get_profile("accounting"), "gl")
    connection.close()

    assert main(["ingest", "erp.db", "--table", "gl", "-o", "l.json"]) == 0
    assert main(["anchor", "l.json", "--batch-size", "25"]) == 0
    assert main(["verify", "l.json"]) == 0


def test_database_tampering_is_detected_after_reingest(workspace, capsys):
    """The motivating scenario: a DBA edits the table directly."""
    import sqlite3

    from ledgerguard.ingest import write_sqlite
    from ledgerguard.profiles import get_profile

    ledger = synth.generate(vouchers=40, seed=3)
    connection = sqlite3.connect(workspace / "erp.db")
    write_sqlite(connection, ledger.records, get_profile("accounting"), "gl")
    connection.close()

    main(["ingest", "erp.db", "--table", "gl", "-o", "base.json"])
    main(["anchor", "base.json", "--batch-size", "50"])

    connection = sqlite3.connect(workspace / "erp.db")
    connection.execute("UPDATE gl SET debit = '1.00' WHERE line_seq = 7")
    connection.execute("DELETE FROM gl WHERE line_seq = 20")
    connection.commit()
    connection.close()

    main(["ingest", "erp.db", "--table", "gl", "-o", "now.json"])
    capsys.readouterr()
    assert main(["verify", "now.json"]) == 1

    out = capsys.readouterr().out
    assert "seq 7: modified" in out
    assert "seq 20: deleted" in out


# -- robustness on bad input -----------------------------------------------
#
# Each of these produced an uncaught traceback before 0.5.2. A command-line
# tool that crashes on a missing file teaches its user to distrust every
# other message it prints.

def test_missing_ledger_file_reports_cleanly(workspace, capsys):
    assert main(["verify", "does-not-exist.json"]) == 2
    err = capsys.readouterr().err
    assert "error:" in err and "Traceback" not in err


def test_missing_database_reports_cleanly(workspace, capsys):
    assert main(["ingest", "no-such.db", "--table", "t", "-o", "l.json"]) == 2
    err = capsys.readouterr().err
    assert "error:" in err and "Traceback" not in err


def test_corrupt_anchor_store_reports_cleanly(workspace, capsys):
    """A damaged anchor file is a finding, not a crash -- and must not be
    confused with a clean verification."""
    main(["generate", "--vouchers", "10", "-o", "l.json"])
    (workspace / "anchors.jsonl").write_text("this is not an anchor\n")
    capsys.readouterr()

    assert main(["verify", "l.json"]) == 2
    err = capsys.readouterr().err
    assert "anchor store" in err and "Traceback" not in err


def test_reading_zero_records_is_an_error_not_an_empty_ledger(workspace, capsys):
    """Pointing at the wrong file used to exit 0 with an empty ledger, pushing
    the failure to `anchor` where the message explained nothing."""
    (workspace / "wrong.json").write_text('{"not": "a csv"}', encoding="utf-8")
    assert main(["ingest", "wrong.json", "-o", "l.json"]) == 2
    assert "read no records" in capsys.readouterr().err
    assert not (workspace / "l.json").exists()


def test_malformed_ledger_json_reports_the_row(workspace, capsys):
    (workspace / "bad.json").write_text('[{"line_seq": 1}]', encoding="utf-8")
    assert main(["verify", "bad.json"]) == 2
    err = capsys.readouterr().err
    assert "row 1" in err and "Traceback" not in err


def test_unparseable_file_reports_cleanly(workspace, capsys):
    (workspace / "junk.json").write_text("not json at all", encoding="utf-8")
    assert main(["anchor", "junk.json"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_verify_reads_around_a_torn_tail_and_leaves_the_store_untouched(
    workspace, capsys
):
    """A crash mid-anchor must not brick the store or pass silently -- and
    verification must not repair it either: checking evidence is not a
    write (0.6.8's verify rewrote the file; found by external audit)."""
    main(["generate", "--vouchers", "10", "-o", "l.json"])
    main(["anchor", "l.json", "--batch-size", "20"])
    store = workspace / "anchors.jsonl"
    with open(store, "ab") as handle:
        handle.write(b'{"torn write from a crash')
    before = store.read_bytes()
    capsys.readouterr()

    assert main(["verify", "l.json"]) == 0
    err = capsys.readouterr().err
    assert "warning" in err and "left untouched" in err
    assert store.read_bytes() == before

    # The next writer repairs it, as before.
    main(["generate", "--vouchers", "5", "--seed", "9", "-o", "m.json"])
    assert main(["anchor", "m.json", "--prefix", "C"]) == 0
    assert "torn write" in capsys.readouterr().err
    assert store.read_bytes().endswith(b"}\n")


# -- 0.6.8: verification must never pass for want of an anchor store --------


def test_verify_against_a_missing_anchor_store_fails_and_creates_nothing(
    workspace, capsys
):
    """Regression: a wrong --anchors path, a wrong working directory or a
    deleted anchor file each used to yield "0 batches verified; no
    discrepancies", exit 0, and a freshly created empty store."""
    main(["generate", "--vouchers", "20", "--seed", "1", "-o", "ledger.json"])
    missing = workspace / "elsewhere" / "anchors.jsonl"

    assert main(["verify", "ledger.json", "--anchors", str(missing)]) == 2

    err = capsys.readouterr().err
    assert "does not exist" in err
    assert not missing.exists()
    assert not missing.parent.exists()


def test_verify_against_an_empty_anchor_store_fails(workspace, capsys):
    main(["generate", "--vouchers", "20", "--seed", "1", "-o", "ledger.json"])
    (workspace / "anchors.jsonl").write_text("")

    assert main(["verify", "ledger.json"]) == 2
    assert "holds no anchors" in capsys.readouterr().err


def test_verify_after_the_anchor_file_is_deleted_fails(workspace):
    """The attack the file simulator is weakest against: remove the evidence."""
    anchored_workspace(workspace)
    (workspace / "anchors.jsonl").unlink()
    assert main(["verify", "ledger.json"]) == 2


def test_anchor_output_does_not_call_the_file_simulator_a_chain(workspace, capsys):
    anchored_workspace(workspace)
    out = capsys.readouterr().out
    assert "file simulator" in out
    assert "committed digests" in out
    assert "on-chain footprint" not in out


# -- 0.6.8: the EVM backend from the command line ---------------------------


@pytest.fixture
def in_process_chain(monkeypatch):
    """Route every --rpc through one in-process EVM for the test's duration."""
    pytest.importorskip("web3", reason="the EVM backend requires web3")
    pytest.importorskip("eth_tester", reason="in-process EVM requires eth-tester")
    from web3 import EthereumTesterProvider, Web3

    from ledgerguard import cli

    w3 = Web3(EthereumTesterProvider())
    monkeypatch.setattr(cli, "_web3_for", lambda rpc: w3)
    return w3


def _deploy(capsys) -> str:
    assert main(["deploy", "--rpc", "http://tester"]) == 0
    address = capsys.readouterr().out.strip().splitlines()[0]
    assert address.startswith("0x") and len(address) == 42
    return address


def test_evm_round_trip_through_the_cli(workspace, capsys, in_process_chain):
    """deploy, anchor, verify and detect on a real contract, with no node."""
    address = _deploy(capsys)
    evm = ["--backend", "evm", "--rpc", "http://tester", "--contract", address,
           "--body-store", "bodies.jsonl"]

    main(["generate", "--vouchers", "40", "--seed", "3", "-o", "ledger.json"])
    assert main(["anchor", "ledger.json", "--batch-size", "25", *evm]) == 0
    out = capsys.readouterr().out
    assert "registry  -> " + address in out
    assert "gas used" in out
    assert not (workspace / "anchors.jsonl").exists()  # nothing simulated
    assert (workspace / "bodies.jsonl").exists()

    assert main(["verify", "ledger.json", *evm]) == 0

    records = read_ledger(workspace / "ledger.json")
    result = tamper.inject(records, seed=1, amount=1, deletion=1)
    write_ledger(workspace / "tampered.json", result.records)
    assert main(["verify", "tampered.json", *evm]) == 1
    assert "1 modified; 1 deleted" in capsys.readouterr().out


def test_evm_verify_against_an_empty_registry_fails(workspace, capsys, in_process_chain):
    address = _deploy(capsys)
    main(["generate", "--vouchers", "10", "--seed", "3", "-o", "ledger.json"])
    (workspace / "bodies.jsonl").write_text("")
    code = main(["verify", "ledger.json", "--backend", "evm", "--rpc", "x",
                 "--contract", address, "--body-store", "bodies.jsonl"])
    assert code == 2
    assert "holds no anchors" in capsys.readouterr().err


@pytest.mark.parametrize("missing", ["--rpc", "--contract"])
def test_evm_backend_names_the_option_it_is_missing(workspace, capsys, missing):
    main(["generate", "--vouchers", "10", "--seed", "3", "-o", "ledger.json"])
    args = ["anchor", "ledger.json", "--backend", "evm"]
    if missing == "--contract":
        args += ["--rpc", "http://tester"]
    else:
        args += ["--contract", "0x" + "0" * 40]
    assert main(args) == 2
    assert missing in capsys.readouterr().err


# -- 0.6.9 ------------------------------------------------------------------


def test_anchoring_an_empty_ledger_is_an_error(workspace, capsys):
    (workspace / "empty.json").write_text("[]")
    assert main(["anchor", "empty.json"]) == 2
    assert "no records" in capsys.readouterr().err
    assert not (workspace / "anchors.jsonl").exists()


def test_every_batch_under_another_schema_is_cannot_verify_not_tampered(
    workspace, capsys
):
    """Exit 2: nothing was verified. Exit 1 would read as "the ledger changed"."""
    anchored_workspace(workspace)
    main(["--profile", "provenance", "generate", "--vouchers", "10",
          "--seed", "1", "-o", "runs.json"])
    capsys.readouterr()

    assert main(["--profile", "provenance", "verify", "runs.json"]) == 2
    assert "different schema" in capsys.readouterr().out


def test_a_partial_schema_mismatch_is_still_a_finding(workspace):
    """Some anchors under another schema: the ledger is checked against the
    rest, and the mismatched ones are reported -- exit 1, not 2."""
    anchored_workspace(workspace)
    main(["--profile", "provenance", "generate", "--vouchers", "10",
          "--seed", "1", "-o", "runs.json"])
    assert main(["--profile", "provenance", "anchor", "runs.json",
                 "--prefix", "P", "--witnesses", "w2.json"]) == 0
    assert main(["verify", "ledger.json"]) == 1


def test_unreachable_rpc_is_reported_not_raised(workspace, capsys):
    pytest.importorskip("web3", reason="the EVM backend requires web3")
    main(["generate", "--vouchers", "10", "--seed", "3", "-o", "ledger.json"])
    code = main(["anchor", "ledger.json", "--backend", "evm",
                 "--rpc", "http://127.0.0.1:1", "--contract", "0x" + "0" * 40])
    assert code == 2
    assert "no Ethereum node answered" in capsys.readouterr().err


# -- 0.6.10 -----------------------------------------------------------------


def test_missing_web3_is_reported_as_an_install_problem(workspace, capsys, monkeypatch):
    """Not as an anchor-store failure: the error subclasses AnchorError."""
    from ledgerguard import evm

    def absent():
        raise evm.MissingDependencyError("the EVM backend requires web3; install ...")

    monkeypatch.setattr(evm, "_require_web3", absent)
    assert main(["deploy", "--rpc", "http://x"]) == 2
    err = capsys.readouterr().err
    assert "requires web3" in err
    assert "anchor store" not in err


def test_anchor_store_that_is_a_directory_is_named_as_such(workspace, capsys):
    main(["generate", "--vouchers", "10", "--seed", "1", "-o", "ledger.json"])
    (workspace / "store").mkdir()
    assert main(["verify", "ledger.json", "--anchors", "store"]) == 2
    err = capsys.readouterr().err
    assert "is a directory" in err and "Errno" not in err
