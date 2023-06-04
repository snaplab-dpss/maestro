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

KERNEL_VERSION=$(uname -r)

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
		ifconfig $iface down || true
	fi
}

bind_dpdk_drivers() {
	pcie_dev=$1

	# Make sure we have the kernel headers.
	# The first 2 get us the uio kernel module, the last 
	# allows us to compile the igb_uio kernel module in DPDK.
	apt install -y \
		linux-generic \
		linux-headers-generic \
		linux-headers-$KERNEL_VERSION

	if ! grep "igb_uio" -q <<< $(lsmod); then
		echo "[$pcie_dev] Loading kernel module igb_uio"

		dpdk_mods="$$RTE_SDK/lib/modules/"

		if [ ! -d $dpdk_mods ] || [ ! grep -q "$KERNEL_VERSION" <<< $(ls $dpdk_mods) ]; then
			echo "[$pcie_dev] igb_uio kernel module not found. Recompiling DPDK."
			pushd $RTE_SDK > /dev/null
				make install \
					-j$(nproc) \
					T=x86_64-native-linuxapp-gcc \
					DESTDIR=. \
					MAKE_PAUSE=n \
					CONFIG_RTE_KNI_KMOD=y \
					CONFIG_RTE_EAL_IGB_UIO=y
			popd > /dev/null
		fi

		modprobe uio
		insmod $RTE_SDK/lib/modules/$KERNEL_VERSION/extra/dpdk/igb_uio.ko
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
