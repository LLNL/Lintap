#!/usr/bin/env bash

set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

log() {
  printf '%s - %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

: "${PIDSTAT_VENV_DIR:=/opt/lintap/pidstat-collector/.venv}"
: "${PIDSTAT_PYTHON:=$PIDSTAT_VENV_DIR/bin/python}"

if [[ "$PIDSTAT_PYTHON" == */* ]]; then
  interpreter="$PIDSTAT_PYTHON"
else
  interpreter="$(command -v "$PIDSTAT_PYTHON" 2>/dev/null || true)"
fi

[[ -n "$interpreter" ]] || fail "could not resolve PIDSTAT_PYTHON=$PIDSTAT_PYTHON"
[[ -x "$interpreter" ]] || fail "collector interpreter is not executable: $interpreter"

exec "$interpreter" "$SCRIPT_DIR/pidstat-collector.py" "$@"
