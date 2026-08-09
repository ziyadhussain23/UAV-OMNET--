#!/usr/bin/env bash
# Build and run the standalone unit tests.
#
# These do not link the OMNeT++ simulation kernel, so they compile and run in
# seconds and serve as the fast gate during development.
#
# Self-registering: each test declares its own dependencies with a comment line
#     // DEPS: core/Bytes.cc core/Encoding.cc
# near the top of the file (paths relative to src/). Adding a test therefore
# requires no edit to this script.
#
# NDEBUG is deliberately NOT defined; the harness uses explicit CHECK macros
# rather than assert(), which the release build would compile away.

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="$ROOT_DIR/src"
TEST_DIR="$ROOT_DIR/tests"
BUILD_DIR="$TEST_DIR/build"
mkdir -p "$BUILD_DIR"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -g -Wall -Wextra -Wno-unused-parameter -I$SRC_DIR -I$ROOT_DIR"
LDLIBS="-lcrypto"

# Foundations first, so the first failure reported is the most fundamental one.
# Any test not listed here still runs, appended in alphabetical order.
PREFERRED_ORDER=(test_encoding test_sha3_suite test_x25519 test_spongent test_ascon
                 test_suite_conformance test_puf test_bch test_fuzzy_extractor
                 test_protocol_offline)

declare -a ORDERED=()
declare -A SEEN=()
for name in "${PREFERRED_ORDER[@]}"; do
    if [ -f "$TEST_DIR/$name.cc" ]; then ORDERED+=("$name"); SEEN[$name]=1; fi
done
for path in "$TEST_DIR"/test_*.cc; do
    [ -e "$path" ] || continue
    name="$(basename "$path" .cc)"
    if [ -z "${SEEN[$name]:-}" ]; then ORDERED+=("$name"); fi
done

if [ "${#ORDERED[@]}" -eq 0 ]; then
    echo "no tests found in $TEST_DIR"
    exit 1
fi

# Optional filter: run_tests.sh <substring>
FILTER="${1:-}"

pass=0
fail=0
failed_names=()

echo "=== building and running unit tests ==="
for name in "${ORDERED[@]}"; do
    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then continue; fi

    src_file="$TEST_DIR/$name.cc"
    deps="$(sed -n 's|^// *DEPS: *||p' "$src_file" | head -1)"
    obj_list=""
    missing=""
    for s in $deps; do
        if [ -f "$SRC_DIR/$s" ]; then
            obj_list="$obj_list $SRC_DIR/$s"
        else
            missing="$missing $s"
        fi
    done

    if [ -n "$missing" ]; then
        echo "SKIP  $name (missing deps:$missing)"
        continue
    fi

    if ! $CXX $CXXFLAGS "$src_file" $obj_list $LDLIBS -o "$BUILD_DIR/$name" \
            2> "$BUILD_DIR/$name.buildlog"; then
        echo "BUILD-FAIL  $name"
        sed 's/^/    /' "$BUILD_DIR/$name.buildlog" | head -30
        fail=$((fail + 1)); failed_names+=("$name (build)")
        continue
    fi

    if "$BUILD_DIR/$name"; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1)); failed_names+=("$name")
    fi
done

echo "=== $pass passed, $fail failed ==="
if [ "$fail" -ne 0 ]; then
    printf 'failed: %s\n' "${failed_names[@]}"
    exit 1
fi
exit 0
