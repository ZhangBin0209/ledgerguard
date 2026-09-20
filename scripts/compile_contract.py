#!/usr/bin/env python3
"""Regenerate the compiled contract artifact from Solidity source.

Users and reviewers do not need to run this: the artifact is committed so
that the package installs and runs without a Solidity toolchain. It exists so
that anyone who wants to check the shipped bytecode against the source can.

Usage:
    python scripts/compile_contract.py [--solc /path/to/solc]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "contracts" / "AnchorRegistry.sol"
ARTIFACT = ROOT / "src" / "ledgerguard" / "artifacts" / "AnchorRegistry.json"

# Pinned so that the bytecode is reproducible. Optimiser settings are part of
# that pin: changing runs changes the bytecode without changing the source.
SOLC_VERSION = "0.8.24"
EVM_VERSION = "paris"
OPTIMIZER_RUNS = 200


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solc", default=shutil.which("solc"))
    parser.add_argument("--check", action="store_true",
                        help="verify the committed artifact matches, do not write")
    args = parser.parse_args()

    if not args.solc:
        print(f"solc not found; install solc {SOLC_VERSION} or pass --solc",
              file=sys.stderr)
        return 2

    result = subprocess.run(
        [args.solc, "--optimize", "--optimize-runs", str(OPTIMIZER_RUNS),
         "--evm-version", EVM_VERSION, "--combined-json", "abi,bin", str(SOURCE)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return result.returncode

    raw = json.loads(result.stdout)
    key = next(k for k in raw["contracts"] if k.endswith("AnchorRegistry"))
    contract = raw["contracts"][key]
    abi = contract["abi"] if isinstance(contract["abi"], list) else json.loads(contract["abi"])

    artifact = {
        "contractName": "AnchorRegistry",
        "source": "contracts/AnchorRegistry.sol",
        "compiler": {
            "name": "solc",
            "version": raw.get("version", SOLC_VERSION),
            "optimizer": {"enabled": True, "runs": OPTIMIZER_RUNS},
            "evmVersion": EVM_VERSION,
        },
        "abi": abi,
        "bytecode": "0x" + contract["bin"],
    }
    rendered = json.dumps(artifact, indent=2, sort_keys=True)

    if args.check:
        current = ARTIFACT.read_text(encoding="utf-8")
        if json.loads(current)["bytecode"] != artifact["bytecode"]:
            print("committed artifact does not match the source", file=sys.stderr)
            return 1
        print("artifact matches the source")
        return 0

    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(rendered, encoding="utf-8")
    print(f"wrote {ARTIFACT.relative_to(ROOT)} "
          f"({len(artifact['bytecode']) // 2} bytes of bytecode)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
