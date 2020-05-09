#!/bin/bash
# $1: "no-verify" to only install compile/runtime dependencies,
#     or no argument to install everything

# Bash "strict mode"
set -euo pipefail

NF_DIR=`pwd`
BUILD="$NF_DIR/build/parallelization"
KLEE_DIR="$VIGOR_DIR/klee"

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
# Run symbex on NF
# ================

cd "$NF_DIR"
make symbex

# ================
# Parse call paths
# ================

"$BUILD/load-call-paths" "$NF_DIR/klee-last/test000012.call_path" 2> /dev/null
