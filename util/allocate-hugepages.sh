#!/bin/bash

HUGEPAGES="/mnt/hugepages2M"

if [ "$EUID" -ne 0 ]; then
	echo "Please run as root."
	exit 1
fi

setup_for_performance() {
	echo "Setting up for performance mode..."
	echo "performance" | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
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

allocate_hugepages
setup_for_performance