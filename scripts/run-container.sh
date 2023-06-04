#!/bin/bash

set -euo pipefail

if [ $# -ne 4 ]; then
	program="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
	echo "Usage: $program [nf] [cores] [PCIe dev 0] [PCIe dev 1]"
	exit 1
fi

NF=$1
CORES=$2
PCIE_DEV0=$3
PCIE_DEV1=$4

docker build . -t "maestro"

docker run \
	--rm \
	--privileged \
	-it \
	-v /mnt:/mnt \
	-v /lib/firmware:/lib/firmware/ \
	-v /sys/devices/system:/sys/devices/system \
	-v /dev:/dev \
	--env DEV0=$PCIE_DEV0 \
	--env DEV1=$PCIE_DEV1 \
	--env HUGE=1 \
	maestro \
	sudo build/apps/$NF --lcores $CORES