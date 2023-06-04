#!/bin/bash

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
	echo "Please run as root."
	exit 1
fi

if [[ -z "${RTE_SDK}" ]]; then
	echo "RTE_SDK env var not set."
	exit 1
fi

if [ $# -eq 0 ]; then
	program="$(basename "$(test -L "$0" && readlink "$0" || echo "$0")")"
	echo "Usage: $program [pcie devices]"
	exit 1
fi

check_pcie_dev() {
	pcie_dev=$1

	if [ -z "$pcie_dev" ]; then
		return 1
	fi
	
	if ! lshw -class network -businfo -quiet | grep -q "$pcie_dev"; then
		echo "[$pcie_dev] PCIe device not found in lshw"
		return 1
	fi

	return 0
}

shutdown_iface() {
	pcie_dev=$1

	iface=$(lshw -class network -businfo -quiet | grep "$pcie_dev" | awk '{ print $2 }')
	
	if [[ "$iface" == "network" ]]; then
		echo "[$pcie_dev] No kernel network interface"
	else
		echo "[$pcie_dev] Bringing interface $iface down"
		sudo ifconfig $iface down
	fi
}

bind_dpdk_drivers() {
	pcie_dev=$1

	if ! grep "igb_uio" -q <<< $(lsmod); then
		echo "[$pcie_dev] Loading kernel module igb_uio"
		modprobe uio

		if ! grep -q "$(uname -r)" <<< $(ls $RTE_SDK/lib/modules/); then
			echo "[$pcie_dev] igb_uio kernel module not found. Recompiling DPDK."
			pushd $RTE_SDK > /dev/null
				make install -j$(nproc) T=x86_64-native-linuxapp-gcc DESTDIR=. MAKE_PAUSE=n
			popd > /dev/null
		fi

		insmod $RTE_SDK/lib/modules/$(uname -r)/extra/dpdk/igb_uio.ko
	fi

	echo "[$pcie_dev] Binding to igb_uio"
	$RTE_SDK/sbin/dpdk-devbind -b igb_uio $pcie_dev
}

for pcie_dev in "$@"; do
	if check_pcie_dev "$pcie_dev"; then
		shutdown_iface "$pcie_dev"
		bind_dpdk_drivers "$pcie_dev"
	fi
done
