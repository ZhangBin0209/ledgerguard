#!/bin/sh
set -e
case "${1:-test}" in
  test)        exec pytest -q ;;
  demo)        exec python demo.py ;;
  bench)       exec ledgerguard benchmark --vouchers 500 ;;
  experiments) shift; exec python scripts/experiments.py --out "${1:-/out}" ;;
  shell)       exec /bin/sh ;;
  *)           exec "$@" ;;
esac
