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

# ================
# Build klee tools
# ================

cd "$KLEE_DIR"
./build.sh
ln -sf "$KLEE_DIR/build/bin/load-call-paths" "$BUILD/load-call-paths"

# ================
# Parse call paths
# ================

CALL_PATHS=$NF_DIR/klee-last/test*.call_path
"$BUILD/load-call-paths" $CALL_PATHS 2> /dev/null
