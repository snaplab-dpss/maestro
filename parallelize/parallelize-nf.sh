#!/bin/bash

# Bash "strict mode"
set -euo pipefail

NF_DIR=`pwd`
BUILD="$NF_DIR/build/parallelization"
KLEE_DIR="$VIGOR_DIR/klee"

# ==============
# Pre requisites
# ==============

cd "$NF_DIR"

if [ $(ls -dq "$NF_DIR/klee-last" 2> /dev/null | wc -l) -eq "0" ]; then
    echo "ERROR: no call paths to parse. Run \"make symbex\" first."
    exit 1
fi

# ===========
# Build setup
# ===========

mkdir -p "$BUILD"

echo "[*] Building parse-libvig-access"

Z3_DIR="$VIGOR_DIR/z3"
R3S_DIR="$VIGOR_DIR/libr3s"

Z3_LIB_FLAGS="-lz3 -Wl,-rpath,$Z3_DIR/build/lib -L$Z3_DIR/build/lib -I$Z3_DIR/build/include"
R3S_LIB_FLAGS="-lr3s -Wl,-rpath,$R3S_DIR/build/lib -L$R3S_DIR/build/lib -I$R3S_DIR/include"

g++ "$NF_DIR/../parallelize/parse-libvig-access.c" \
    -o "$BUILD/parse-libvig-access" \
    $Z3_LIB_FLAGS \
    $R3S_LIB_FLAGS

echo "[*] Building load-call-paths"

cd "$KLEE_DIR"
./build.sh > "$BUILD/klee-build-log.txt" 2>&1
ln -sf "$KLEE_DIR/build/bin/load-call-paths" "$BUILD/load-call-paths"
cd "$NF_DIR"

# ================
# Parse call paths
# ================

echo "[*] Parsing call paths"
CALL_PATHS=$NF_DIR/klee-last/test*.call_path
"$BUILD/load-call-paths" $CALL_PATHS \
    2> "$BUILD/livbig-access-log.txt" \
    > "$BUILD/livbig-access-out.txt"

echo "[*] Parsing libvig report"
"$BUILD/parse-libvig-access" "$BUILD/livbig-access-out.txt"
