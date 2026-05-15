#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v opp_run >/dev/null 2>&1; then
    echo "OMNeT++ runtime tools not found. Source your OMNeT++ environment first (e.g., source setenv)."
    exit 1
fi

cd "$ROOT_DIR"

EXECUTABLE="$ROOT_DIR/src/uavauthsim"
if [[ ! -x "$EXECUTABLE" ]]; then
    echo "Executable not found: $EXECUTABLE"
    echo "Build first using scripts/build_omnet_project.sh"
    exit 1
fi

"$EXECUTABLE" -u Cmdenv \
    -n "$ROOT_DIR/src;$ROOT_DIR/simulations" \
    -f "$ROOT_DIR/simulations/omnetpp.ini" \
    -c Baseline
