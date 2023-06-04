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
	echo "Usage: $program [pcie devices...]"
	exit 1
fi

HUGEPAGES="/mnt/hugepages2M"

check_pcie_dev() {
	pcie_dev=$1
	
	if ! lshw -class network -businfo -quiet | grep -q "$pcie_dev"; then
		echo "[$pcie_dev] PCIe device not found in lshw"
		exit 1
	fi
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

allocate_hugepages() {
	echo "Allocating hugepages..."

	mkdir -p $HUGEPAGES
	mount -t hugetlbfs -o pagesize=2M none $HUGEPAGES

	# ~64 MB of hugepages
	su -c "echo 4092 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"
	su -c "echo 4092 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages"

	allocated=$(grep "HugePages_Total" /proc/meminfo | awk '{print $2}')

	if [ "$allocated" -eq 0 ]; then
		echo "Hugepage allocation failed"
		echo "/proc/meminfo content:"
		echo ""
		grep "Huge" /proc/meminfo
		echo ""
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

setup_for_performance() {
	echo "Setting up for performance mode..."
	echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
}

allocate_hugepages
setup_for_performance

echo "Binding $@ to igb_uio..."
for pcie_dev in "$@"; do
	check_pcie_dev "$pcie_dev"
	shutdown_iface "$pcie_dev"
	bind_dpdk_drivers "$pcie_dev"
done
