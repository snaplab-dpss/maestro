#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd)

function cleanup {
  sudo killall nf 2>/dev/null || true
  sudo killall tcpreplay 2>/dev/null || true
  sudo killall psd.py 2>/dev/null || true
}
trap cleanup EXIT

function test_psd {
  CAPACITY=$1
  MAX_PORTS=$2
  EXPIRATION_TIME=$3

  python3 psd.py --output psd.pcap

  sudo ./build/app/nf \
        --vdev "net_tap0,iface=test_wan" \
        --vdev "net_tap1,iface=test_lan" \
        --lcores 0 \
        --no-huge \
        --no-shconf -- \
        --capacity $CAPACITY \
        --max-ports $MAX_PORTS \
        --expire $EXPIRATION_TIME &
  NF_PID=$!

  while [ ! -f /sys/class/net/test_lan/tun_flags -o \
          ! -f /sys/class/net/test_lan/tun_flags ]; do
    echo "Waiting for NF to launch...";
    sleep 1;
  done

  sudo tcpreplay -M 10 -i "test_wan" --duration 10 -K -l 10000 psd.pcap > /dev/null 2>/dev/null

  sudo killall nf
  wait $NF_PID 2>/dev/null || true
}

make clean
make EXTRA_CFLAGS="-O0 -g -DENABLE_LOG"

capacity=65536
max_ports=64
expiration_time=1000000

test_psd $capacity $max_ports $expiration_time
