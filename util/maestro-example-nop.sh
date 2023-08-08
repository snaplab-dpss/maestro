#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
MAESTRO_DIR="$SCRIPT_DIR/../"
PATHS_SCRIPT="$MAESTRO_DIR/paths.sh"
NFS_DIR="$MAESTRO_DIR/dpdk-nfs/"
MAESTRO_SCRIPT="$MAESTRO_DIR/maestro/maestro.py"
OUT_DIR="$MAESTRO_DIR/synthesized"

setup() {
	. $PATHS_SCRIPT
	mkdir -p $OUT_DIR
}

generate() {
	nf=$1
	target=$2

	nf_name=$(basename $nf)
	nf_out="$OUT_DIR/$nf_name-$target.c"

	echo "Generating $nf_name for target $target..."

	$MAESTRO_SCRIPT $nf --target $target --out "$nf_out"

	echo "Generated $nf_out"
}

generate_all_targets() {
	nf=$1
	generate $nf "seq"
	generate $nf "sn"
	generate $nf "locks"
	generate $nf "tm"
}

generate_nop() {
	generate_all_targets $NFS_DIR/nop
}

setup
generate_nop
