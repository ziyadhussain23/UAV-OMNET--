#!/usr/bin/env bash
set -euo pipefail

# Build helper for the OMNeT++ UAV authentication project.
#
# All cryptography is provided by OpenSSL 3.x (SHA3, HMAC, HKDF, ChaCha20-Poly1305,
# X25519), so -lcrypto is the only external dependency. SPONGENT-160 and Ascon-128a
# are vendored under src/crypto/ and need no link flags.
#
# Optional environment flags:
#   BUILD_MODE=debug   -> build with MODE=debug (asserts live; default is release)

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT_DIR/src"

if ! command -v opp_makemake >/dev/null 2>&1; then
    echo "opp_makemake not found. Source your OMNeT++ environment first:"
    echo "    source ~/omnetpp-6.3.0/setenv"
    echo "    export PATH=\"\$HOME/omnetpp-6.3.0/bin:\$PATH\""
    exit 1
fi

MODE="${BUILD_MODE:-release}"

cd "$SRC_DIR"

# -I.  makes every header reachable as "crypto/CryptoSuite.h" from anywhere in the
#      tree, instead of fragile relative paths like "../crypto/CryptoSuite.h".
# --deep re-globs all .cc under src/, so newly added files are picked up. The
#      generated Makefile has a STATIC object list, which is why this script must be
#      re-run after adding or removing a source file (never plain `make`).
opp_makemake -f --deep -I. -o uavauthsim -lcrypto

make MODE="$MODE"

echo "Build finished: $SRC_DIR/uavauthsim (MODE=$MODE)"
