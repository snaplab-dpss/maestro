#!/bin/bash

set -euo pipefail

function help {
  echo "Usage: $0 nf-dir pcap [pcap loops]" >&2
  exit 1
}

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
TOOLS=$SCRIPT_DIR/tools
BUILD=$SCRIPT_DIR/build
SYNTHESIZED=$BUILD/synthesized

if [ "$#" -lt 2 ] || ! [ -d "$1" ]; then
  help
fi

NF_DIR=$1
PCAP=$2
LOOPS=1

if ! test -f "$PCAP" || ! file "$PCAP" | grep -q "pcap"; then
  echo "$PCAP not found or not a pcap file."
  help
fi

if [ "$#" -gt 2 ]; then
  re='^[0-9]+$'
  if ! [[ $3 =~ $re ]]; then
    echo "$3 not a number" >&2
    help
  fi
  LOOPS=$3
fi

if ! test -f "$NF_DIR/nf.bdd"; then
  pushd $NF_DIR
    make bdd
  popd
fi

mkdir -p $SYNTHESIZED

# Generating the call path hit analyzer source file
$KLEE_BUILD_PATH/bin/bdd-to-c -in $NF_DIR/nf.bdd -out $SYNTHESIZED/nf-cph.c -target cph

# Building the call path hit analyzer binary
$TOOLS/build.py $SYNTHESIZED/nf-cph.c call_path_hitter --nf $NF_DIR

# Generating the call path hit rate report
$BUILD/app/nf --no-huge -- --pcap $PCAP --loops $LOOPS

# Generating call path hit rate graphviz file
$KLEE_BUILD_PATH/bin/call-path-hit-rate-graphviz-generator \
  -in $NF_DIR/nf.bdd -report $SCRIPT_DIR/nf-cph.tsv -out $SCRIPT_DIR/nf-cph.gv