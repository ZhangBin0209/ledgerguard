#!/usr/bin/env python3
"""Draw the two-layer architecture figure used as Fig. 1 of the paper.

    python scripts/architecture_figure.py --out results/fig0_architecture

The figure has three bands. Domain profiles at the top supply a schema and
domain rules. The domain-independent core in the middle imports nothing from
profiles/. The harness at the bottom -- synthetic generation, tamper
injection and the command-line tool -- is profile-aware by design and sits
outside the core; an earlier hand-drawn version placed it inside, which the
text contradicted. Arrows follow the data: the Merkle root flows into the commitment, backends
receive commitments, and only a 32-byte digest per batch reaches a chain.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

GREEN, GREEN_FILL = "#4a7d2a", "#e9f2df"
BLUE, BLUE_FILL = "#2c4f7c", "#dbe7f5"
GREY, GREY_FILL = "#555555", "#f1f1f1"
INK = "#222222"


def box(ax, x, y, w, h, title, sub, edge, fill, title_size=13):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
        linewidth=1.4, edgecolor=edge, facecolor=fill, zorder=2))
    ax.text(x + w / 2, y + h * 0.62, title, ha="center", va="center",
            fontsize=title_size, fontweight="bold", color=INK, zorder=3)
    ax.text(x + w / 2, y + h * 0.27, sub, ha="center", va="center",
            fontsize=10, style="italic", color="#444444", zorder=3)
    return (x, y, w, h)


def edge_point(b, side):
    x, y, w, h = b
    return {"top": (x + w / 2, y + h), "bottom": (x + w / 2, y),
            "left": (x, y + h / 2), "right": (x + w, y + h / 2)}[side]


def arrow(ax, p, q, color=INK, style="-", lw=1.4, label=None, label_dy=0.12,
          label_size=9.5, connection="arc3,rad=0"):
    ax.add_patch(FancyArrowPatch(
        p, q, arrowstyle="-|>", mutation_scale=14, linewidth=lw,
        color=color, linestyle=style, connectionstyle=connection,
        shrinkA=2, shrinkB=2, zorder=4))
    if label:
        ax.text((p[0] + q[0]) / 2, (p[1] + q[1]) / 2 + label_dy, label,
                ha="center", va="bottom", fontsize=label_size, style="italic",
                color=color, zorder=5)


def band(ax, y, label, color):
    ax.text(0.35, y + 0.12, label, fontsize=15, fontweight="bold", color=color)
    ax.plot([0.35, 13.65], [y, y], linestyle=(0, (1, 3)), linewidth=1.2,
            color="#999999")


def draw() -> plt.Figure:
    fig, ax = plt.subplots(figsize=(14, 9.6), dpi=150)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 9.6)
    ax.axis("off")

    # -- band 1: profiles ---------------------------------------------------
    band(ax, 8.55, "Domain profiles", GREEN)
    acc = box(ax, 1.4, 7.25, 4.2, 1.0, "accounting", "journal_entry v1",
              GREEN, GREEN_FILL)
    prov = box(ax, 7.0, 7.25, 4.2, 1.0, "provenance", "instrument_event v1",
               GREEN, GREEN_FILL)
    ax.text(12.6, 7.75, "no shared\nfield names", ha="center", va="center",
            fontsize=11, style="italic", color=GREEN)

    # -- band 2: core -------------------------------------------------------
    band(ax, 6.05, "Domain-independent core", BLUE)
    ax.text(13.65, 6.17, "imports nothing from profiles/", ha="right",
            fontsize=10, style="italic", color=BLUE)

    ingest = box(ax, 0.55, 4.55, 2.15, 1.0, "ingest", "CSV / SQLite", GREY, GREY_FILL)
    schema = box(ax, 3.35, 4.55, 2.15, 1.0, "schema", "typed fields", BLUE, BLUE_FILL)
    canon = box(ax, 3.35, 2.85, 2.15, 1.0, "canonical", "record → bytes", BLUE, BLUE_FILL)
    merkle = box(ax, 6.2, 4.55, 2.15, 1.0, "merkle", "RFC 6962 / 9162", BLUE, BLUE_FILL)
    commit = box(ax, 6.2, 2.85, 2.15, 1.0, "commitment", "3 assertions", BLUE, BLUE_FILL)
    backends = box(ax, 9.05, 2.85, 2.15, 1.0, "backends", "memory / file / EVM",
                   BLUE, BLUE_FILL)
    chain = box(ax, 11.8, 2.85, 1.85, 1.0, "chain", "32 B digest / batch", GREY, GREY_FILL)
    verifier = box(ax, 9.05, 4.55, 2.15, 1.0, "verifier", "3-tier findings",
                   BLUE, BLUE_FILL)

    # profiles -> schema
    for b in (acc, prov):
        arrow(ax, edge_point(b, "bottom"), edge_point(schema, "top"),
              color=GREEN, style="--", lw=1.3)
    ax.text(7.7, 6.55, "a profile supplies a RecordSchema and its domain rules",
            ha="left", fontsize=10.5, style="italic", color=GREEN)

    # data flow inside the core
    arrow(ax, edge_point(ingest, "right"), edge_point(schema, "left"),
          label="records")
    arrow(ax, edge_point(schema, "bottom"), edge_point(canon, "top"))
    arrow(ax, edge_point(canon, "right"), edge_point(commit, "left"),
          label="digests")
    # The root flows from the tree into the commitment, not the other way.
    arrow(ax, edge_point(merkle, "bottom"), edge_point(commit, "top"))
    ax.text(7.28, 4.05, "root", ha="left", va="center", fontsize=9.5,
            style="italic", color=INK)
    arrow(ax, edge_point(commit, "right"), edge_point(backends, "left"))
    arrow(ax, edge_point(backends, "right"), edge_point(chain, "left"),
          label="digest")
    arrow(ax, edge_point(backends, "top"), edge_point(verifier, "bottom"))
    ax.text(10.28, 4.05, "anchors", ha="left", va="center", fontsize=9.5,
            style="italic", color=INK)
    # witness, off-chain: commitment -> (around the backends) -> verifier
    wx, wy = 11.5, 2.3
    ax.plot([7.275, 7.275, wx, wx], [2.85, wy, wy, 5.05], linestyle="--",
            linewidth=1.1, color="#444444", zorder=4)
    arrow(ax, (wx, 5.05), edge_point(verifier, "right"), style="--", lw=1.1,
          color="#444444")
    ax.text(9.4, 2.12, "witness (off-chain, untrusted until checked\nagainst the anchored root)",
            ha="center", va="top", fontsize=9.5, style="italic", color="#444444")

    # -- band 3: harness ----------------------------------------------------
    band(ax, 1.55, "Experiment harness and CLI", GREY)
    ax.text(13.65, 1.67, "profile-aware by design: imports from profiles/",
            ha="right", fontsize=10, style="italic", color=GREY)
    synth = box(ax, 0.55, 0.3, 2.15, 0.95, "synth", "seeded ledgers", GREY, GREY_FILL, 12)
    tamper = box(ax, 3.35, 0.3, 2.15, 0.95, "tamper", "ground truth", GREY, GREY_FILL, 12)
    box(ax, 6.2, 0.3, 7.45, 0.95, "cli",
              "ingest · generate · deploy · anchor · verify · benchmark",
              GREY, GREY_FILL, 12)
    arrow(ax, edge_point(synth, "right"), edge_point(tamper, "left"), lw=1.2)
    arrow(ax, edge_point(tamper, "top"), edge_point(canon, "bottom"), lw=1.2,
          label="records", label_dy=0.0, label_size=9)
    ax.text(9.925, 1.38, "drives the pipeline above; binds --profile and --backend",
            ha="center", va="bottom", fontsize=9.5, style="italic", color=GREY)

    fig.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
    return fig


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="results/fig0_architecture", type=Path,
                        help="output path without extension; .png and .pdf are written")
    args = parser.parse_args()
    fig = draw()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.out.with_suffix(".png"))
    fig.savefig(args.out.with_suffix(".pdf"))
    print(f"wrote {args.out}.png and .pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
