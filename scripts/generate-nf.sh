#!/bin/bash

set -euo pipefail

NF=$1

if [ $# -eq 0 ]; then
	program="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
	echo "Usage: $program NF"
	exit 1
fi

if [[ -z "${MAESTRO_DIR}" ]]; then
	echo "MAESTRO_DIR env var not set."
	exit 1
fi

. $MAESTRO_DIR/build/paths.sh

NF_PATH="$MAESTRO_DIR/dpdk-nfs/$NF"

if [ ! -d "$NF_PATH" ]; then
	echo "$NF_PATH does not exist."
	exit 1
fi

MAESTRO="$MAESTRO_DIR/dpdk-nfs/synthesized/tools/maestro.py"
OUT_DIR="$MAESTRO_DIR/apps"


setup() {
	mkdir -p $OUT_DIR
	pushd "$MAESTRO_DIR/dpdk-nfs/synthesized" >/dev/null
		make maestro -j
	popd >/dev/null
}

generate() {
	nf_name=$1
	nf_path=$2
	target=$3

	$MAESTRO $nf_path --target $target
	cp "$MAESTRO_DIR/dpdk-nfs/synthesized/build/app/nf" "$OUT_DIR/$nf_name-$target"
}

setup
generate $NF $NF_PATH "seq"
generate $NF $NF_PATH "sn"
generate $NF $NF_PATH "locks"
generate $NF $NF_PATH "tm"