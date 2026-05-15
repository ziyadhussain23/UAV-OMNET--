#!/usr/bin/env bash
set -euo pipefail

# Build helper for the OMNeT++ UAV authentication project.
# Optional environment flags:
#   USE_LIBCORRECT=1 -> compile with -DUSE_LIBCORRECT -lcorrect
#   USE_SODIUM=1     -> compile with -DUSE_SODIUM -lsodium

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT_DIR/src"

if ! command -v opp_makemake >/dev/null 2>&1; then
    echo "opp_makemake not found. Source your OMNeT++ environment first (e.g., source setenv)."
    exit 1
fi

EXTRA_CFLAGS=""
EXTRA_LIBS="-lcrypto"   # SHA3Hash.cc uses OpenSSL EVP unconditionally

if [[ "${USE_LIBCORRECT:-0}" == "1" ]]; then
    EXTRA_CFLAGS+=" -DUSE_LIBCORRECT"
    EXTRA_LIBS+=" -lcorrect"
fi

if [[ "${USE_SODIUM:-0}" == "1" ]]; then
    EXTRA_CFLAGS+=" -DUSE_SODIUM"
    EXTRA_LIBS+=" -lsodium"
fi

cd "$SRC_DIR"

ARGS=(-f --deep -o uavauthsim)

if [[ -n "$EXTRA_CFLAGS" ]]; then
    # shellcheck disable=SC2206
    DEFS=($EXTRA_CFLAGS)
    ARGS+=("${DEFS[@]}")
fi

if [[ -n "$EXTRA_LIBS" ]]; then
    # shellcheck disable=SC2206
    LIBFLAGS=($EXTRA_LIBS)
    ARGS+=("${LIBFLAGS[@]}")
fi

opp_makemake "${ARGS[@]}"

make MODE=release

echo "Build finished: $SRC_DIR/uavauthsim"
