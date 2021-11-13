#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)
TARGET_SUBNET_SZ=11

function cleanup {
  sudo killall nf 2>/dev/null || true
  sudo killall tcpreplay 2>/dev/null || true
  sudo killall hhh.py 2>/dev/null || true
}
trap cleanup EXIT

function test_hhh {
  LINK=$1
  THRESHOLD=$2
  MIN_PREFIX=$3
  MAX_PREFIX=$4
  BURST=$5

  python3 hhh.py --output hhh.pcap --sz $TARGET_SUBNET_SZ

  sudo ./build/app/nf \
        --vdev "net_tap0,iface=test_wan" \
        --vdev "net_tap1,iface=test_lan" \
        --no-shconf -- \
        --lan 1 \
        --wan 0 \
        --link $LINK \
        --threshold $THRESHOLD \
        --min-prefix $MIN_PREFIX \
        --max-prefix $MAX_PREFIX \
        --burst $BURST \
        --capacity 65536 &
  NF_PID=$!

  while [ ! -f /sys/class/net/test_lan/tun_flags -o \
          ! -f /sys/class/net/test_lan/tun_flags ]; do
    echo "Waiting for NF to launch...";
    sleep 1;
  done

  sudo tcpreplay -M 10 -i "test_wan" --duration 10 -K -l 10000 hhh.pcap > /dev/null 2>/dev/null

  sudo killall nf
  wait $NF_PID 2>/dev/null || true
}

make clean
make EXTRA_CFLAGS="-O0 -g -DENABLE_LOG"

test_hhh 1000000 70 8 32 500000
