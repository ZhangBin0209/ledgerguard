#!/usr/bin/env python3
"""Reproducible measurement harness.

Runs every experiment reported for LedgerGuard and writes the results to
``results/`` as both CSV and figures. One script, one command, so that a
reader can re-derive the reported numbers rather than take them on trust:

    python scripts/experiments.py --out results/

Five experiments:

``throughput``
    Anchoring cost as a function of ledger size. Establishes that the
    pipeline is linear in record count and quantifies the constant. Every
    timing is the median of ``--repeats`` calls and carries its within-run
    spread; with ``--runs N`` the whole experiment is repeated N times, the
    per-run medians go to ``throughput_runs.csv``, and ``throughput.csv``
    reports the median across runs together with the run-to-run spread --
    the figure that separates measurement noise from a trend.

``batch-size``
    The central trade-off. On-chain cost falls with batch size while the
    tampering-localisation window grows, so the choice is an operating point
    rather than a tuning detail.

``proof``
    Inclusion proof size and verification time against batch size, confirming
    the logarithmic scaling the Merkle construction promises.

``detection``
    Detection rate per attack class at several tampering rates, with false
    positives, over repeated seeds.

``gas``
    Gas per anchoring transaction against batch size, measured on a real EVM
    running in process (``eth-tester``). Skipped, with a note, when ``web3``
    is not installed. This is the honest on-chain cost figure: the 32 bytes
    per batch quoted elsewhere is the committed digest, not what the
    registry's storage grows by.

Hardware and software versions are recorded in ``results/environment.json``
so that reported timings can be interpreted and re-measured elsewhere.
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ledgerguard import (
    BatchBuilder,
    MemoryBackend,
    Verdict,
    Verifier,
    synth,
    tamper,
)
from ledgerguard.profiles.accounting import JOURNAL_ENTRY_V1
from ledgerguard.tamper import AttackClass

SCHEMA = JOURNAL_ENTRY_V1


# --------------------------------------------------------------------------
# Timing
# --------------------------------------------------------------------------


def timed(fn: Callable[[], Any], repeats: int = 3) -> tuple[float, Any]:
    """Median wall-clock seconds over ``repeats`` runs, and the last result.

    The median rather than the minimum: the minimum reports the best case the
    machine ever managed, which is not what a user experiences, and the mean
    is pulled around by scheduler noise.
    """
    median, _spread, result = timed_with_spread(fn, repeats)
    return median, result


def timed_with_spread(
    fn: Callable[[], Any], repeats: int = 3
) -> tuple[float, float, Any]:
    """Median seconds, the (max - min) / median spread across repeats, and
    the last result.

    The spread is recorded beside every throughput figure so a reader can
    tell measurement noise from a trend: on a shared virtual machine,
    run-to-run variation of 20% is ordinary and larger than any effect of
    ledger size.
    """
    durations = []
    result = None
    for _ in range(repeats):
        start = time.perf_counter()
        result = fn()
        durations.append(time.perf_counter() - start)
    median = statistics.median(durations)
    spread = (max(durations) - min(durations)) / median if median else 0.0
    return median, spread, result


def anchor_ledger(records: Sequence[dict], batch_size: int):
    """Batch, commit and anchor a ledger. Returns the backend and witnesses."""
    backend = MemoryBackend()
    witnesses = {}
    chunks = [records[i : i + batch_size] for i in range(0, len(records), batch_size)]
    for index, chunk in enumerate(chunks):
        builder = BatchBuilder(SCHEMA, f"B{index:05d}", backend.next_prev_digest())
        builder.extend(chunk)
        batch = builder.seal()
        backend.anchor(batch.commitment)
        witnesses[batch.commitment.batch_id] = batch.witness()
    return backend, witnesses


# --------------------------------------------------------------------------
# Experiment 1: throughput
# --------------------------------------------------------------------------


def experiment_throughput(sizes: Sequence[int], repeats: int) -> list[dict]:
    rows = []
    for vouchers in sizes:
        ledger = synth.generate(vouchers=vouchers, seed=0)
        n = len(ledger)

        from ledgerguard import record_digest

        digest_time, _ = timed(
            lambda: [record_digest(r, SCHEMA) for r in ledger.records],
            repeats,
        )
        anchor_time, anchor_spread, (backend, witnesses) = timed_with_spread(
            lambda: anchor_ledger(ledger.records, 100), repeats
        )
        verify_time, verify_spread, _ = timed_with_spread(
            lambda: Verifier(backend, SCHEMA).verify_ledger(
                ledger.records, witnesses),
            repeats,
        )

        rows.append({
            "records": n,
            "batches": len(witnesses),
            "repeats": repeats,
            "digest_s": round(digest_time, 6),
            "anchor_s": round(anchor_time, 6),
            "verify_s": round(verify_time, 6),
            "anchor_records_per_s": round(n / anchor_time),
            "verify_records_per_s": round(n / verify_time),
            "anchor_spread": round(anchor_spread, 4),
            "verify_spread": round(verify_spread, 4),
        })
        print(f"  {n:>7} records  anchor {n/anchor_time:>9,.0f} rec/s "
              f"(±{anchor_spread:.0%})  verify {n/verify_time:>9,.0f} rec/s "
              f"(±{verify_spread:.0%})")
    return rows


def aggregate_runs(runs: Sequence[Sequence[dict]]) -> list[dict]:
    """Collapse several runs of :func:`experiment_throughput` into one table.

    For each ledger size: the median across runs of the per-run median
    times, the largest within-run spread any run showed, and the run-to-run
    spread ``(max - min) / median`` of the per-run medians. With a single
    run the run-to-run columns are zero and the table is that run.
    """
    by_size: dict[int, list[dict]] = {}
    for run in runs:
        for row in run:
            by_size.setdefault(row["records"], []).append(row)

    def spread(values: Sequence[float]) -> float:
        med = statistics.median(values)
        return (max(values) - min(values)) / med if med else 0.0

    out = []
    for records, rows in sorted(by_size.items()):
        n = records
        anchor_s = statistics.median(r["anchor_s"] for r in rows)
        verify_s = statistics.median(r["verify_s"] for r in rows)
        out.append({
            "records": n,
            "batches": rows[0]["batches"],
            "repeats": rows[0]["repeats"],
            "runs": len(rows),
            "digest_s": round(statistics.median(r["digest_s"] for r in rows), 6),
            "anchor_s": round(anchor_s, 6),
            "verify_s": round(verify_s, 6),
            "anchor_records_per_s": round(n / anchor_s),
            "verify_records_per_s": round(n / verify_s),
            "anchor_spread": round(max(r["anchor_spread"] for r in rows), 4),
            "verify_spread": round(max(r["verify_spread"] for r in rows), 4),
            "anchor_run_spread": round(spread([r["anchor_s"] for r in rows]), 4),
            "verify_run_spread": round(spread([r["verify_s"] for r in rows]), 4),
        })
    return out


# --------------------------------------------------------------------------
# Experiment 2: batch size trade-off
# --------------------------------------------------------------------------


def experiment_batch_size(vouchers: int, batch_sizes: Sequence[int],
                          repeats: int) -> list[dict]:
    ledger = synth.generate(vouchers=vouchers, seed=1)
    n = len(ledger)
    rows = []
    for size in batch_sizes:
        anchor_time, (_, witnesses) = timed(
            lambda: anchor_ledger(ledger.records, size), repeats
        )
        batches = len(witnesses)
        rows.append({
            "batch_size": size,
            "records": n,
            "batches": batches,
            # 32 bytes per batch is the committed digest -- the value that
            # reaches a chain. It is not the registry's storage footprint,
            # which adds a fixed few words of metadata per batch; see the
            # ``gas`` experiment for the measured cost.
            "digest_bytes": batches * 32,
            "digest_bytes_per_record": round(batches * 32 / n, 4),
            # Without a witness, a root mismatch localises tampering only to a
            # batch, so batch size is the size of the ambiguity window. This
            # column is that definition written out, not a measurement.
            "localisation_window": size,
            "anchor_s": round(anchor_time, 6),
        })
        print(f"  batch {size:>6}  {batches:>5} batches  "
              f"{batches * 32:>7} digest bytes  "
              f"{batches * 32 / n:.3f} B/record")
    return rows


# --------------------------------------------------------------------------
# Experiment 3: proof size and verification cost
# --------------------------------------------------------------------------


def experiment_proof(batch_sizes: Sequence[int], repeats: int) -> list[dict]:
    rows = []
    for size in batch_sizes:
        ledger = synth.generate(vouchers=size, seed=2)
        records = ledger.records[:size]
        builder = BatchBuilder(SCHEMA, "B0")
        builder.extend(records)
        batch = builder.seal()

        middle = len(batch) // 2
        proof = batch.prove(middle) if hasattr(batch, "prove") else batch.tree.prove(middle)
        verify_time, _ = timed(lambda: proof.verify(batch.commitment.root),
                               max(repeats * 100, 100))

        rows.append({
            "batch_size": len(batch),
            "proof_hashes": len(proof.path),
            "proof_bytes": len(proof.path) * 32,
            "verify_us": round(verify_time * 1e6, 3),
        })
        print(f"  batch {len(batch):>6}  proof {len(proof.path):>3} hashes "
              f"({len(proof.path) * 32:>5} B)  verify {verify_time * 1e6:>8.1f} us")
    return rows


# --------------------------------------------------------------------------
# Experiment 4: detection rate
# --------------------------------------------------------------------------


def experiment_detection(vouchers: int, rates: Sequence[float],
                         seeds: Sequence[int]) -> list[dict]:
    rows = []
    for rate in rates:
        for seed in seeds:
            ledger = synth.generate(vouchers=vouchers, seed=seed)
            backend, witnesses = anchor_ledger(ledger.records, 100)
            result = tamper.inject_proportional(
                ledger.records, rate=rate, seed=seed)
            report = Verifier(backend, SCHEMA).verify_ledger(
                result.records, witnesses)

            flagged = {
                v: {f.sequence for b in report.batches for f in b.by_verdict(v)}
                for v in Verdict
            }
            detected_by = {
                AttackClass.AMOUNT: flagged[Verdict.MODIFIED],
                AttackClass.PERIOD: flagged[Verdict.MODIFIED],
                AttackClass.DELETION: flagged[Verdict.DELETED],
                AttackClass.SEQUENCE: flagged[Verdict.INSERTED],
            }
            row: dict[str, Any] = {
                "rate": rate, "seed": seed, "records": len(ledger),
                "injected": len(result.log),
            }
            for attack in AttackClass:
                truth = result.log.sequences_of(attack)
                hits = truth & detected_by[attack]
                row[f"{attack.value}_injected"] = len(truth)
                row[f"{attack.value}_detected"] = len(hits)
                row[f"{attack.value}_recall"] = (
                    round(len(hits) / len(truth), 4) if truth else None
                )

            all_flagged = set().union(
                *(flagged[v] for v in Verdict if v is not Verdict.INTACT))
            row["false_positives"] = len(all_flagged - result.log.sequences)
            rows.append(row)
        print(f"  rate {rate:.3%}  seeds {len(seeds)}  "
              f"mean FP {statistics.mean(r['false_positives'] for r in rows[-len(seeds):]):.1f}")
    return rows


# --------------------------------------------------------------------------
# Experiment 5: gas per anchoring transaction
# --------------------------------------------------------------------------


def experiment_gas(batch_sizes: Sequence[int]) -> list[dict]:
    """Gas used by ``AnchorRegistry.anchor`` as batch size varies.

    Returns an empty list, after printing why, when web3 or eth-tester is
    absent; the other experiments do not depend on either.
    """
    try:
        import eth_tester  # noqa: F401
        import web3  # noqa: F401
    except ImportError:
        print("  web3/eth-tester not installed; skipping (pip install "
              "'ledgerguard[dev]')")
        return []
    from ledgerguard.evm import EVMBackend

    ledger = synth.generate(vouchers=max(batch_sizes), seed=3)
    records = ledger.records
    chain = EVMBackend.in_memory_chain()
    rows = []
    # The very first anchor on a fresh registry pays extra to take the
    # insertion-index length slot from zero to one, which is a property of
    # the registry rather than of the batch. It is measured separately so the
    # per-batch figure is not distorted by it.
    warm = BatchBuilder(SCHEMA, "warm-up", chain.next_prev_digest())
    warm.extend(records[:1])
    chain.anchor(warm.seal().commitment)
    first_anchor_gas = chain.last_gas_used

    for size in batch_sizes:
        builder = BatchBuilder(SCHEMA, f"G{size:06d}", chain.next_prev_digest())
        builder.extend(records[:size])
        batch = builder.seal()
        chain.anchor(batch.commitment)
        gas = chain.last_gas_used or 0
        rows.append({
            "batch_size": len(batch),
            "gas_used": gas,
            "gas_per_record": round(gas / len(batch), 2),
            "first_anchor_gas": first_anchor_gas,
        })
        print(f"  batch {len(batch):>6}  {gas:>8,} gas  "
              f"{gas / len(batch):>10,.1f} gas/record")
    spread = max(r["gas_used"] for r in rows) - min(r["gas_used"] for r in rows)
    print(f"  spread across batch sizes: {spread} gas "
          f"(first anchor on a fresh registry: {first_anchor_gas:,})")
    return rows


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def write_csv(path: Path, rows: Sequence[dict]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _cpu_model() -> str:
    """The CPU's marketing name, where the platform exposes it.

    ``platform.processor()`` returns "x86_64" on Linux, which says nothing
    about the machine the timings came from.
    """
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def write_environment(path: Path) -> None:
    import os

    import ledgerguard

    info = {
        "ledgerguard_version": ledgerguard.__version__,
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(info, indent=2), encoding="utf-8")


def make_figures(out: Path, throughput, batch_rows, proof_rows, detection_rows):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib not installed; skipping figures")
        return

    plt.rcParams.update({"font.size": 9, "figure.dpi": 150,
                         "axes.grid": True, "grid.alpha": 0.3})

    # Fig 1: throughput
    fig, ax = plt.subplots(figsize=(5, 3.2))
    x = [r["records"] for r in throughput]
    ax.plot(x, [r["anchor_s"] for r in throughput], "o-", label="anchor")
    ax.plot(x, [r["verify_s"] for r in throughput], "s-", label="verify")
    ax.set_xlabel("records")
    ax.set_ylabel("seconds")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_title("Anchoring and verification cost")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "fig1_throughput.pdf")
    fig.savefig(out / "fig1_throughput.png")
    plt.close(fig)

    # Fig 2: the batch-size trade-off, two axes
    fig, ax = plt.subplots(figsize=(5, 3.2))
    sizes = [r["batch_size"] for r in batch_rows]
    ax.plot(sizes, [r["digest_bytes_per_record"] for r in batch_rows], "o-", color="C0")
    ax.set_xlabel("batch size (records)")
    ax.set_ylabel("committed digest bytes per record", color="C0")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.tick_params(axis="y", labelcolor="C0")
    twin = ax.twinx()
    twin.plot(sizes, [r["localisation_window"] for r in batch_rows], "s--", color="C3")
    twin.set_ylabel("localisation window (records, = batch size)", color="C3")
    twin.set_yscale("log")
    twin.tick_params(axis="y", labelcolor="C3")
    twin.grid(False)
    ax.set_title("Batch size: cost against localisation")
    fig.tight_layout()
    fig.savefig(out / "fig2_batch_tradeoff.pdf")
    fig.savefig(out / "fig2_batch_tradeoff.png")
    plt.close(fig)

    # Fig 3: proof size
    fig, ax = plt.subplots(figsize=(5, 3.2))
    ax.plot([r["batch_size"] for r in proof_rows],
            [r["proof_bytes"] for r in proof_rows], "o-")
    ax.set_xlabel("batch size (records)")
    ax.set_ylabel("proof size (bytes)")
    ax.set_xscale("log")
    ax.set_title("Inclusion proof size is logarithmic in batch size")
    fig.tight_layout()
    fig.savefig(out / "fig3_proof_size.pdf")
    fig.savefig(out / "fig3_proof_size.png")
    plt.close(fig)

    # Fig 4: detection recall per class
    fig, ax = plt.subplots(figsize=(5, 3.2))
    rates = sorted({r["rate"] for r in detection_rows})
    width = 0.2
    for i, attack in enumerate(AttackClass):
        means = []
        for rate in rates:
            values = [r[f"{attack.value}_recall"] for r in detection_rows
                      if r["rate"] == rate and r[f"{attack.value}_recall"] is not None]
            means.append(statistics.mean(values) if values else 0.0)
        ax.bar([j + i * width for j in range(len(rates))], means,
               width, label=attack.value)
    ax.set_xticks([j + 1.5 * width for j in range(len(rates))])
    ax.set_xticklabels([f"{r:.1%}" for r in rates])
    ax.set_xlabel("tampering rate")
    ax.set_ylabel("recall")
    ax.set_ylim(0, 1.15)
    ax.set_title("Detection rate by attack class")
    ax.legend(ncol=4, fontsize=7, loc="upper center")
    fig.tight_layout()
    fig.savefig(out / "fig4_detection.pdf")
    fig.savefig(out / "fig4_detection.png")
    plt.close(fig)

    print(f"  wrote 4 figures (pdf + png) to {out}")


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="results", type=Path)
    parser.add_argument("--repeats", type=int, default=5,
                        help="timed repeats per measurement (median reported)")
    parser.add_argument("--runs", type=int, default=1,
                        help="independent repetitions of the throughput "
                             "experiment; per-run medians go to "
                             "throughput_runs.csv, the run-to-run spread to "
                             "throughput.csv")
    parser.add_argument("--quick", action="store_true",
                        help="smaller parameter sweeps, for a smoke test")
    args = parser.parse_args()

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    if args.quick:
        sizes = [50, 200, 800]
        batch_sizes = [10, 50, 200, 1000]
        proof_sizes = [16, 128, 1024]
        rates = [0.01, 0.05]
        seeds = [0, 1]
    else:
        sizes = [100, 500, 2_000, 10_000, 40_000]
        batch_sizes = [10, 50, 100, 500, 1_000, 5_000]
        proof_sizes = [16, 64, 256, 1_024, 4_096, 16_384]
        rates = [0.001, 0.005, 0.01, 0.05]
        seeds = [0, 1, 2, 3, 4]

    print("environment")
    write_environment(out / "environment.json")
    print(f"  -> {out / 'environment.json'}")

    print("\n[1/5] throughput")
    runs = []
    for run in range(max(args.runs, 1)):
        if args.runs > 1:
            print(f"  run {run + 1}/{args.runs}")
        runs.append(experiment_throughput(sizes, args.repeats))
    if args.runs > 1:
        write_csv(out / "throughput_runs.csv",
                  [{"run": i + 1, **row} for i, run in enumerate(runs) for row in run])
    throughput = aggregate_runs(runs)
    write_csv(out / "throughput.csv", throughput)
    if args.runs > 1:
        worst = max(max(r["anchor_run_spread"], r["verify_run_spread"]) for r in throughput)
        print(f"  run-to-run spread across {args.runs} runs: up to {worst:.0%}")

    print("\n[2/5] batch-size trade-off")
    batch_rows = experiment_batch_size(
        sizes[-1] if args.quick else 5_000, batch_sizes, args.repeats)
    write_csv(out / "batch_size.csv", batch_rows)

    print("\n[3/5] proof size")
    proof_rows = experiment_proof(proof_sizes, args.repeats)
    write_csv(out / "proof_size.csv", proof_rows)

    print("\n[4/5] detection rate")
    detection_rows = experiment_detection(
        200 if args.quick else 2_000, rates, seeds)
    write_csv(out / "detection.csv", detection_rows)

    print("\n[5/5] gas per anchoring transaction")
    gas_rows = experiment_gas(batch_sizes)
    write_csv(out / "gas.csv", gas_rows)

    print("\nfigures")
    make_figures(out, throughput, batch_rows, proof_rows, detection_rows)

    print(f"\nall results in {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
