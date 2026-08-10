#!/usr/bin/env bash
# Build the INET/802.11-MAC-contention track (Phase 2 of the future-work plan).
#
# Deliberately a SEPARATE executable (uavauthsim_inet) from a SEPARATE source
# tree (src_inet/) -- a plain `scripts/build_omnet_project.sh` run is never
# affected by this at all: that script's `opp_makemake --deep` runs from
# inside src/ and never sees src_inet/, and this script never touches src/'s
# own Makefile.
#
# src_inet/apps/ reuses src/{core,crypto,fe,protocol,puf} (the
# transport-agnostic layer) verbatim. opp_makemake's directory-scanning flags
# (--deep, -d, -X) turned out not to support "flatten these two disjoint
# trees, minus one subdirectory, into one Makefile" cleanly -- --deep only
# ever reaches subdirectories of the invocation directory, and -d triggers
# recursive sub-make (needs the target to have its own self-sufficient
# Makefile), neither of which fits. So this script instead compiles the
# reused layer into a small static archive directly (matching the exact
# compiler flags OMNeT++'s own generated Makefiles use, so ABI/optimisation
# stay consistent), and points opp_makemake's normal single-directory scan
# (of src_inet/ only) at that archive as a link input.
#
# Requires: INET already built in release mode at the path below (see
# REPORT3.md / the future-work plan for how that build was produced).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INET_ROOT="${INET_ROOT:-$HOME/oment-workspace2/inet4.5}"
INET_LIB_DIR="$INET_ROOT/out/clang-release/src"

if ! command -v opp_makemake >/dev/null 2>&1; then
    echo "opp_makemake not found. Source your OMNeT++ environment first:"
    echo "    source ~/omnetpp-6.3.0/setenv"
    echo "    export PATH=\"\$HOME/omnetpp-6.3.0/bin:\$PATH\""
    exit 1
fi

if [ ! -f "$INET_LIB_DIR/libINET.so" ]; then
    echo "libINET.so not found at $INET_LIB_DIR"
    echo "Build INET in release mode first: cd \$INET_ROOT/src && make MODE=release -j\$(nproc)"
    exit 1
fi

CXX="${CXX:-clang++}"
CORE_DIRS="core crypto fe protocol puf"
ARCHIVE_DIR="$ROOT_DIR/src_inet/out/clang-release/core"
mkdir -p "$ARCHIVE_DIR"

echo "Compiling the reused transport-agnostic layer (src/{$CORE_DIRS// /,}) ..."
OBJ_FILES=()
for dir in $CORE_DIRS; do
    while IFS= read -r -d '' f; do
        # Flatten the relative path into the object's basename (crypto/ has
        # spongent/ and ascon/ subdirectories) so two files can't collide.
        rel="${f#"$ROOT_DIR"/src/}"
        obj="$ARCHIVE_DIR/${rel//\//_}"
        obj="${obj%.cc}.o"
        "$CXX" -std=c++17 -O3 -DNDEBUG=1 -g1 -ffp-contract=off -fPIC \
            -I"$ROOT_DIR/src" -c "$f" -o "$obj"
        OBJ_FILES+=("$obj")
    done < <(find "$ROOT_DIR/src/$dir" -name "*.cc" -print0)
done
ar rcs "$ARCHIVE_DIR/libuavauthcore.a" "${OBJ_FILES[@]}"

cd "$ROOT_DIR/src_inet"
opp_makemake -f --deep \
    -I. -I.. -I"$ROOT_DIR/src" -I"$INET_ROOT/src" \
    -L"$INET_LIB_DIR" -lINET -lcrypto \
    "$ARCHIVE_DIR/libuavauthcore.a" \
    -o uavauthsim_inet -O out

make MODE=release -j"$(nproc)"

echo "Build finished: $ROOT_DIR/src_inet/out/clang-release/uavauthsim_inet"
echo "Run with LD_LIBRARY_PATH including: $INET_LIB_DIR"
