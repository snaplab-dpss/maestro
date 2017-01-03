#!/bin/bash
. ./config.sh

# Master script to benchmark VigNAT-related programs.
# Can benchmark different implementations, including non-NATs,
# using different scenarios.

# Parameters:
# $1: The app, either a known name or a DPDK NAT-like app.
#     Known names: "netfilter".
#     Otherwise, a folder name containing a DPDK NAT-like app, e.g. "~/vnds/nat"
# $2: The scenario, one of the following:
#     "loopback": Measure throughput.
#                 Tester and middlebox are connected together in a loop,
#                 using 2 interfaces on each, in different subnets; server is ignored.
#     "1p": Measure throughput.
#           Find the point at which the middlebox starts dropping 1% of packets.
#     "passthrough": Measure latency.
#                    Tester sends packets to server, which pass through the middlebox;
#                    all machines are in the same subnet.
#     "rr": Measure latency.
#           Tester sends packets to server, which are modified by the middlebox;
#           there are two subnets, tester-middlebox and middlebox-server.
#           a.k.a. request/response

if [ -z $1 ]; then
    echo "[bench] No app specified" 1>&2
    exit 1
fi

if [ -z $2 ]; then
    echo "[bench] No scenario specified" 1>&2
    exit 2
fi


# First, initialize the network;
# to do that, we need to know whether we'll run a DPDK app or not.
MIDDLEBOX_APP="dpdk"
if [ $1 = "netfilter" ]; then
    MIDDLEBOX_APP="netfilter"
fi

. ./init-network.sh $2 $MIDDLEBOX_APP


RESULTS_FILE="bench-$1-$2.results"
LOG_FILE="bench-$1-$2.log"


if [ $1 = "netfilter" ]; then
    # Nothing to do, already configured by init-network
else
    echo "[bench] Launching $1..."
    # Run the app in the background
    (./bench/run-dpdk.sh \
        $1 \
        # The arguments are not always necessary, but they'll be ignored if unneeded
        "--expire 10 --max-flows 61000 --starting-port 1025" \
        # Close stdin, redirect output to a log file (useful iff something goes wrong)
        0<&- &>$LOG_FILE) &

    # Wait for it to have started
    sleep 20
fi


# Then, run the benchmark depending on the scenario
case $2 in
    "loopback"|"1p")
        LUA_SCRIPT="regular-with-bin-mf"
        if [ $2 = "1p" ]; then
            LUA_SCRIPT="find-breaking-point-mf"
        fi

        echo "[bench] Benchmarking throughput..."
        ssh $TESTER_HOST "bash ~/scripts/pktgen-scripts/run.sh ~/scripts/pktgen-scripts/$LUA_SCRIPT.lua"
        scp $TESTER_HOST:pktgen/multi-flows.txt ./$RESULTS_FILE
        ssh $TESTER_HOST "rm pktgen/multi-flows.txt"
        ;;

    "passthrough"|"rr")
        # No difference from a benchmarking point of view, only setup varies

        echo "[bench] Benchmarking latency..."
        ssh $TESTER_HOST "bash ~/scripts/bench/latency.sh ~/bench.results"
        scp $TESTER_HOST:bench.results ./$RESULTS_FILE
        ssh $TESTER_HOST "rm ~/bench.results"
        ;;

    *)
        echo "[bench] Unknown scenario: $1" 1>&2
        exit 10
        ;;
esac
