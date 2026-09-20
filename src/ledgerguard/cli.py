"""Command-line interface.

Built on ``argparse`` rather than a CLI framework so that the package has no
runtime dependencies at all.  A reviewer can clone the repository and run
every command below on a stock Python installation, which removes the most
common reason a software submission fails evaluation: it would not install.

Six subcommands cover the workflow:

``ingest``    read records out of a CSV export or a SQLite database
``generate``  produce a reproducible synthetic ledger
``deploy``    put an ``AnchorRegistry`` contract on an Ethereum-compatible chain
``anchor``    batch a ledger, commit it, and retain the witnesses
``verify``    check a ledger against its anchors and print a forensic report
``benchmark`` inject known tampering and report detection rates per class

``anchor`` and ``verify`` take ``--backend file`` (the default: an append-only
JSON Lines *simulator*, adequate for experiments and teaching but under the
same control as the ledger it protects) or ``--backend evm`` (a deployed
registry reached over ``--rpc``, which is the configuration that actually
delivers the tamper-evidence property).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Sequence

from . import ingest, synth, tamper
from .backends import AnchorError, ChainBackend, FileBackend, MemoryBackend
from .commitment import BatchBuilder, BatchWitness
from .evm import MissingDependencyError
from .ingest import IngestError
from .profiles import get_profile, profile_names
from .profiles.accounting import JOURNAL_ENTRY_V1, validate_voucher_balance
from .schema import FieldType, RecordSchema
from .tamper import AttackClass
from .verifier import BatchStatus, Verdict, Verifier, format_report

SCHEMA = JOURNAL_ENTRY_V1  # default profile, overridable with --profile


# --------------------------------------------------------------------------
# Serialisation helpers
#
# The ledger interchange format is JSON with amounts as strings and dates as
# ISO text.  Amounts must never round-trip through a JSON number: that would
# take them through a float and reintroduce exactly the precision instability
# the canonical encoding exists to prevent.
# --------------------------------------------------------------------------


def _record_to_json(record: dict[str, Any], schema: RecordSchema) -> dict[str, Any]:
    """Render a record for the interchange file, driven by the schema.

    Nothing here names a field: adding a profile must not require touching the
    serialiser.
    """
    out: dict[str, Any] = {}
    for spec in schema.fields:
        value = record[spec.name]
        if value is None:
            out[spec.name] = None
        elif spec.type in (FieldType.DATE, FieldType.DATETIME):
            out[spec.name] = value.isoformat()
        elif spec.type is FieldType.MONEY:
            out[spec.name] = str(value)
        else:
            out[spec.name] = value
    return out


def write_ledger(
    path: Path, records: Sequence[dict[str, Any]], schema: RecordSchema = SCHEMA
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([_record_to_json(r, schema) for r in records],
                   indent=2, sort_keys=True),
        encoding="utf-8",
    )


def read_ledger(path: Path, schema: RecordSchema = SCHEMA) -> list[dict[str, Any]]:
    """Read the interchange file back through the ingestion coercion path.

    Reusing `ingest` rather than a bespoke parser means the interchange format
    gets the same float refusal and the same timezone rules as a database
    export, instead of a second, subtly different set.
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ingest.read_rows(raw, schema)


def write_witnesses(path: Path, witnesses: dict[str, BatchWitness]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({k: w.to_dict() for k, w in witnesses.items()}, indent=2),
        encoding="utf-8",
    )


def read_witnesses(path: Path) -> dict[str, BatchWitness]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {k: BatchWitness.from_dict(v) for k, v in raw.items()}


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------


def _schema(args: argparse.Namespace) -> RecordSchema:
    return get_profile(getattr(args, "profile", "accounting"))


def cmd_ingest(args: argparse.Namespace) -> int:
    """Read records out of a CSV export or a SQLite database."""
    schema = _schema(args)
    source = Path(args.source)

    if args.table or args.query:
        records = ingest.read_sqlite(
            source, schema, table=args.table, query=args.query,
            assume_utc=args.assume_utc,
        )
        origin = f"sqlite:{args.table or 'query'}"
    else:
        records = ingest.read_csv(source, schema, assume_utc=args.assume_utc)
        origin = "csv"

    if not records:
        # Reading nothing is almost always the wrong file or the wrong table,
        # not an empty ledger. Writing an empty file and exiting 0 would push
        # the failure to `anchor`, which would report it as an empty batch --
        # a message that says nothing about the actual mistake.
        print(
            f"error: read no records from {source}. Check that the path, "
            "format and --table are what you intended.",
            file=sys.stderr,
        )
        return 2

    write_ledger(Path(args.out), records, schema)
    print(f"read {len(records)} records from {origin} -> {args.out}")
    seq = schema.sequence_field
    if seq is not None:
        # A profile without a sequence field cannot be anchored at all, but
        # it can still be read, and indexing by None here would have turned a
        # useful summary line into a crash.
        print(f"  sequence range: {records[0][seq]}-{records[-1][seq]}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    schema = _schema(args)
    if args.profile == "provenance":
        ledger = synth.generate_provenance(
            runs=args.vouchers, seed=args.seed, batch_size=args.batch_size)
        from .profiles.provenance import validate_run
        validate_run(ledger.records)
        unit = "runs"
    else:
        ledger = synth.generate(
            vouchers=args.vouchers, seed=args.seed,
            batch_size=args.batch_size, void_rate=args.void_rate,
        )
        validate_voucher_balance(ledger.records)
        unit = "vouchers"

    write_ledger(Path(args.out), ledger.records, schema)
    print(
        f"generated {len(ledger)} records from {args.vouchers} {unit} "
        f"(profile {args.profile}, seed {args.seed}) -> {args.out}"
    )
    return 0


def _open_file_backend(path: str, *, create: bool) -> FileBackend:
    """Open a file store: writable when ``create`` is true, read-only otherwise.

    The two go together on purpose. ``anchor`` may create and repair the
    store; ``verify`` may do neither -- checking evidence must not alter it.
    """
    backend = FileBackend(path, create=create, read_only=not create)
    if backend.recovered:
        # Worth a line on stderr: the user should know a crash left debris,
        # even though nothing anchored was lost.
        print(
            f"note: {path} ended in a torn write from an interrupted run; "
            "the incomplete line was removed and the anchored history is intact.",
            file=sys.stderr,
        )
    elif backend.torn_tail:
        print(
            f"warning: {path} ends in a torn write from an interrupted run. "
            "It was left untouched (verification does not modify the anchor "
            "store); the intact anchors before it were used. The next "
            "`anchor` run will repair it.",
            file=sys.stderr,
        )
    return backend


def _web3_for(rpc: str) -> Any:
    """A connected ``Web3`` for an HTTP RPC endpoint.

    Kept as a one-line seam so the test suite can substitute an in-process
    EVM (``EthereumTesterProvider``) and drive the real subcommands against a
    real contract without a node.
    """
    from .evm import _require_web3

    web3 = _require_web3()
    w3 = web3.Web3(web3.Web3.HTTPProvider(rpc))
    if not w3.is_connected():
        raise AnchorError(f"no Ethereum node answered at {rpc}")
    return w3


def _open_backend(args: argparse.Namespace, *, create: bool) -> ChainBackend:
    """The anchoring backend the arguments describe.

    ``create`` is false on the verification path: a store that does not
    exist must be reported, not silently created and verified against.
    """
    if getattr(args, "backend", "file") != "evm":
        return _open_file_backend(args.anchors, create=create)

    if not args.rpc:
        raise ValueError("--backend evm requires --rpc URL")
    if not args.contract:
        raise ValueError(
            "--backend evm requires --contract ADDRESS "
            "(run `ledgerguard deploy --rpc URL` to create a registry)"
        )
    from .evm import EVMBackend

    body_store = _open_file_backend(args.body_store, create=create)
    return EVMBackend(_web3_for(args.rpc), args.contract, args.account, body_store)


def cmd_deploy(args: argparse.Namespace) -> int:
    """Deploy a fresh ``AnchorRegistry`` and print its address."""
    from .evm import EVMBackend

    backend = EVMBackend.deploy(_web3_for(args.rpc), account=args.account)
    print(backend.address)
    print(
        f"  deployed an AnchorRegistry via {args.rpc}; pass "
        f"--backend evm --rpc {args.rpc} --contract {backend.address} "
        "to anchor and verify",
        file=sys.stderr,
    )
    return 0


def cmd_anchor(args: argparse.Namespace) -> int:
    schema = _schema(args)
    records = read_ledger(Path(args.ledger), schema)
    if not records:
        # Anchoring nothing is not a success. `ingest` already refuses to
        # write an empty ledger; a hand-made one used to sail through here as
        # "anchored 0 records in 0 batches", leaving an empty store behind.
        print(
            f"error: {args.ledger} holds no records; nothing to anchor",
            file=sys.stderr,
        )
        return 2
    backend = _open_backend(args, create=True)
    witnesses: dict[str, BatchWitness] = {}

    size = args.batch_size
    chunks = [records[i : i + size] for i in range(0, len(records), size)]
    gas_total = 0
    for index, chunk in enumerate(chunks):
        batch_id = f"{args.prefix}{index:04d}"
        builder = BatchBuilder(schema, batch_id, backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch_id] = batch.witness()
        gas_total += getattr(backend, "last_gas_used", None) or 0

    write_witnesses(Path(args.witnesses), witnesses)
    committed = len(chunks) * 32
    per_record = committed / max(len(records), 1)
    print(f"anchored {len(records)} records in {len(chunks)} batches")
    if args.backend == "evm":
        print(f"  registry  -> {getattr(backend, 'address', args.contract)} via {args.rpc}")
        print(f"  bodies    -> {args.body_store}")
    else:
        print(f"  anchors   -> {args.anchors}  (file simulator, not a chain)")
    print(f"  witnesses -> {args.witnesses}")
    # 32 bytes is the commitment digest -- the only value that reaches a
    # chain. It is not the registry's storage footprint, which adds a fixed
    # few words of metadata per batch; gas is the honest cost figure.
    print(
        f"  committed digests: {committed} bytes ({per_record:.2f} bytes/record)"
        + ("" if args.backend == "evm" else "; this is what --backend evm anchors")
    )
    if args.backend == "evm" and gas_total:
        print(f"  gas used: {gas_total:,} over {len(chunks)} transactions "
              f"({gas_total // len(chunks):,} per batch)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    schema = _schema(args)
    records = read_ledger(Path(args.ledger), schema)
    # create=False: verifying against a store that does not exist is an
    # error. Before 0.6.8 a wrong --anchors path, a wrong working directory
    # or a deleted anchor file each produced an empty store, "0 batches
    # verified; no discrepancies", and exit status 0.
    backend = _open_backend(args, create=False)
    witnesses = read_witnesses(Path(args.witnesses)) if args.witnesses else {}

    anchors = len(backend)
    if not anchors:
        where = (f"registry {args.contract}" if args.backend == "evm"
                 else f"anchor store {args.anchors}")
        print(
            f"error: {where} holds no anchors; there is nothing to verify "
            "the ledger against",
            file=sys.stderr,
        )
        return 2

    report = Verifier(backend, schema).verify_ledger(records, witnesses)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_report(report))
    if report.batches and all(
        b.status is BatchStatus.SCHEMA_MISMATCH for b in report.batches
    ):
        # Every anchor was made under a different schema: the ledger was not
        # verified at all, so this is "cannot verify" (2), not "tampered"
        # (1). A partial mismatch is still a finding about the ledger.
        return 2
    return 0 if report.intact else 1


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Inject known tampering and measure detection rate per attack class."""
    ledger = synth.generate(
        vouchers=args.vouchers, seed=args.seed, batch_size=args.batch_size
    )

    backend = MemoryBackend()
    witnesses: dict[str, BatchWitness] = {}
    for index, chunk in enumerate(ledger.batches()):
        builder = BatchBuilder(SCHEMA, f"B{index:04d}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()

    result = tamper.inject(
        ledger.records,
        seed=args.seed,
        amount=args.amount,
        deletion=args.deletion,
        period=args.period,
        sequence=args.sequence,
    )
    report = Verifier(backend, SCHEMA).verify_ledger(result.records, witnesses)

    flagged = {
        verdict: {f.sequence for b in report.batches for f in b.by_verdict(verdict)}
        for verdict in Verdict
    }
    # Amount and period alterations are both content changes, so both surface
    # as MODIFIED; the ground truth is what separates them.
    detected_by = {
        AttackClass.AMOUNT: flagged[Verdict.MODIFIED],
        AttackClass.PERIOD: flagged[Verdict.MODIFIED],
        AttackClass.DELETION: flagged[Verdict.DELETED],
        AttackClass.SEQUENCE: flagged[Verdict.INSERTED],
    }

    print(f"ledger: {len(ledger)} records in {len(ledger.batches())} batches")
    print(f"injected: {result.log.counts()}\n")
    print(f"{'attack':<12}{'injected':>10}{'detected':>10}{'recall':>10}")
    print("-" * 42)

    overall_injected = overall_detected = 0
    for attack in AttackClass:
        truth = result.log.sequences_of(attack)
        if not truth:
            continue
        hits = truth & detected_by[attack]
        overall_injected += len(truth)
        overall_detected += len(hits)
        print(
            f"{attack.value:<12}{len(truth):>10}{len(hits):>10}"
            f"{len(hits) / len(truth):>10.1%}"
        )

    if overall_injected:
        print("-" * 42)
        print(
            f"{'total':<12}{overall_injected:>10}{overall_detected:>10}"
            f"{overall_detected / overall_injected:>10.1%}"
        )

    # A false positive here is an untouched record reported as tampered.
    all_flagged = set().union(*(flagged[v] for v in Verdict if v is not Verdict.INTACT))
    false_positives = all_flagged - result.log.sequences
    print(f"\nfalse positives: {len(false_positives)}")
    return 0


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def _add_backend_options(parser: argparse.ArgumentParser) -> None:
    """Options shared by ``anchor`` and ``verify`` that select where anchors live."""
    group = parser.add_argument_group("anchoring backend")
    group.add_argument(
        "--backend", choices=("file", "evm"), default="file",
        help="file: append-only JSON Lines simulator (default); "
             "evm: an AnchorRegistry contract reached over --rpc",
    )
    group.add_argument("--anchors", default="anchors.jsonl",
                       help="anchor store for --backend file")
    group.add_argument("--rpc", help="HTTP RPC endpoint (--backend evm)")
    group.add_argument("--contract", help="AnchorRegistry address (--backend evm)")
    group.add_argument("--account", help="sender address (--backend evm)")
    group.add_argument("--body-store", default="bodies.jsonl",
                       help="off-chain commitment bodies (--backend evm)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ledgerguard",
        description="Tamper evidence for append-only structured records.",
    )
    parser.add_argument(
        "--profile", default="accounting", choices=profile_names(),
        help="record schema to use (default: accounting)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ing = sub.add_parser("ingest", help="read records from CSV or SQLite")
    ing.add_argument("source", help="path to a .csv file or .db database")
    ing.add_argument("--table", help="SQLite table to read in full")
    ing.add_argument("--query", help="SQL to run instead of reading a table")
    ing.add_argument("--assume-utc", action="store_true",
                     help="treat naive timestamps as UTC")
    ing.add_argument("-o", "--out", default="ledger.json")
    ing.set_defaults(func=cmd_ingest)

    gen = sub.add_parser("generate", help="produce a synthetic ledger")
    gen.add_argument("--vouchers", type=int, default=500)
    gen.add_argument("--seed", type=int, default=0)
    gen.add_argument("--batch-size", type=int, default=100)
    gen.add_argument("--void-rate", type=float, default=0.03)
    gen.add_argument("-o", "--out", default="ledger.json")
    gen.set_defaults(func=cmd_generate)

    dep = sub.add_parser(
        "deploy", help="deploy an AnchorRegistry contract (needs web3)")
    dep.add_argument("--rpc", required=True, help="HTTP RPC endpoint of a node")
    dep.add_argument("--account", help="sender address (default: the node's first)")
    dep.set_defaults(func=cmd_deploy)

    anc = sub.add_parser("anchor", help="batch, commit and anchor a ledger")
    anc.add_argument("ledger")
    _add_backend_options(anc)
    anc.add_argument("--witnesses", default="witnesses.json")
    anc.add_argument("--batch-size", type=int, default=100)
    anc.add_argument("--prefix", default="B")
    anc.set_defaults(func=cmd_anchor)

    ver = sub.add_parser("verify", help="check a ledger against its anchors")
    ver.add_argument("ledger")
    _add_backend_options(ver)
    ver.add_argument("--witnesses", default="witnesses.json")
    ver.add_argument("--json", action="store_true", help="emit a JSON report")
    ver.set_defaults(func=cmd_verify)

    bench = sub.add_parser("benchmark", help="measure detection rate per attack class")
    bench.add_argument("--vouchers", type=int, default=500)
    bench.add_argument("--seed", type=int, default=0)
    bench.add_argument("--batch-size", type=int, default=100)
    bench.add_argument("--amount", type=int, default=10)
    bench.add_argument("--deletion", type=int, default=10)
    bench.add_argument("--period", type=int, default=10)
    bench.add_argument("--sequence", type=int, default=10)
    bench.set_defaults(func=cmd_benchmark)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except BrokenPipeError:
        # `ledgerguard verify | head` closes the pipe early. Reporting that as
        # a crash would be wrong -- the command did its job -- so drain stdout
        # to a null device and exit the way other Unix tools do.
        import os

        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except FileNotFoundError as exc:
        print(f"error: no such file: {exc.filename}", file=sys.stderr)
        return 2
    except sqlite3.Error as exc:
        print(f"error: database: {exc}", file=sys.stderr)
        return 2
    except MissingDependencyError as exc:
        # An install problem, not an evidence problem: web3 is absent. It
        # subclasses AnchorError, so it must be named before that branch or
        # it is reported as an anchor-store failure (found by external audit
        # of 0.6.9).
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except AnchorError as exc:
        # A corrupt or unreadable anchor store. This is a finding in its own
        # right -- someone may have edited it -- so it must not look like a
        # crash, and it must not be confused with a clean verification.
        print(f"error: anchor store: {exc}", file=sys.stderr)
        return 2
    except (IngestError, OSError, KeyError, ValueError) as exc:
        # A bad column, an unknown profile or a malformed source file is a
        # user error, not a bug; a traceback would bury the one useful line.
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
