#!/usr/bin/env bash
# Thin wrapper: run the full cunho stress harness against a source dir.
# Usage: tools/stress/run_all.sh SOURCE_DIR [--quick] [--out DIR] [--soak-seconds N] [--suites 1,2,4]
# Python: $CUNHO_STRESS_PYTHON, else tools/stress/.venv, else the repo's .venv (it needs hypothesis and psutil).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${CUNHO_STRESS_PYTHON:-}"
if [ -z "$PY" ]; then
  if [ -x "$HERE/.venv/bin/python" ]; then PY="$HERE/.venv/bin/python"; else PY="$HERE/../../.venv/bin/python"; fi
fi
exec "$PY" "$HERE/run_all.py" "$@"
