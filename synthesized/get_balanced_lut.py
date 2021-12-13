#!/usr/bin/python3
#-*- coding: utf-8 -*-

# Test data including the secret key, ip, port numbers and the hash values 
# as the result is from "Intel Ethernet Controller 710 Series Datasheet".

import random
import argparse
import sys
import copy
import math
import numpy
import time

from functools import partial

from os import system, listdir
from os.path import isfile, join

from scapy.all import *
from scapy.utils import PcapWriter

from multiprocessing import Pool

from numpy import percentile

MAX_CORES=16
LUT_SIZE=512

PCAP_PARTITIONS_MAX_SIZE = 100 # MB
PCAP_PARTITIONS_BASENAME = 'pcap_partition'

CONFIG = {
	'key': [],
	'verbose': False
}

def rss(pkt):
	assert(CONFIG['key'])
	key = copy.deepcopy(CONFIG['key'])

	def hash_to_lut_index(hash_value):
		return hash_value & 0x1ff

	def left_most_32bits_of_key():
		return (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3]

	def shift_key():
		bitstr = ''
		for k in key:
		   bitstr += bin(k)[2:].zfill(8)
		shifted = bitstr[1:]
		shifted += bitstr[0]
		for i, k in enumerate(key):
			key[i] = int(shifted[:8], 2)
			shifted = shifted[8:]

	def compute_hash(input_bytes):
		result = 0;
		bitstr = ''
		for b in input_bytes:
			bitstr += bin(b)[2:].zfill(8) # eliminate prefix "0b" and fill zeros to fit into 8 bits
		for b in bitstr:
			if b == '1':
				result ^= left_most_32bits_of_key()
			shift_key()
		return result

	def get_ip_number(ip):
		ipnum = str(ip).split('.')
		return int(ipnum[0]) << 24 | int(ipnum[1]) << 16 | int(ipnum[2]) << 8 | int(ipnum[3])

	def get_input(srcip, dstip, srcport, dstport):
		input_bytes = []
		input_bytes.append((srcip & 0xff000000) >> 24)
		input_bytes.append((srcip & 0x00ff0000) >> 16)
		input_bytes.append((srcip & 0x0000ff00) >> 8)
		input_bytes.append(srcip & 0x000000ff)
		input_bytes.append((dstip & 0xff000000) >> 24)
		input_bytes.append((dstip & 0x00ff0000) >> 16)
		input_bytes.append((dstip & 0x0000ff00) >> 8)
		input_bytes.append(dstip & 0x000000ff)
		input_bytes.append((srcport & 0xff00) >> 8)
		input_bytes.append(srcport & 0x00ff)
		input_bytes.append((dstport & 0xff00) >> 8)
		input_bytes.append(dstport & 0x00ff)
		return input_bytes

	srcip = get_ip_number(pkt["IP"].src)
	dstip = get_ip_number(pkt["IP"].dst)
	sport = int(pkt["UDP"].sport)
	dport = int(pkt["UDP"].dport)

	hash_input = get_input(srcip, dstip, sport, dport)
	hash_value = compute_hash(hash_input)

	return hash_to_lut_index(hash_value)

def lut_counter_from_pcap(pcap):
	pkts = PcapReader(pcap)
	n_pkts = 0
	lut = [ 0 ] * LUT_SIZE

	for pkt in pkts:
		n_pkts += 1
		lut[rss(pkt)] += 1

	return lut

def partition_pcap(pcap):
	assert(PCAP_PARTITIONS_MAX_SIZE > 0 and int(PCAP_PARTITIONS_MAX_SIZE) == PCAP_PARTITIONS_MAX_SIZE)
	out_pipes = '> /dev/null 2>&1' if not CONFIG['verbose'] else ''
	system(f"tcpdump -r {pcap} -w {PCAP_PARTITIONS_BASENAME} -C {PCAP_PARTITIONS_MAX_SIZE} {out_pipes}")
	return [ p for p in listdir('.') if isfile(join('.', p)) and PCAP_PARTITIONS_BASENAME in p ]

def delete_partitions(partitions):
	for p in partitions:
		system(f"rm {p}")

def lut_counters_to_core_counters(cores, lut, lut_counters):
	core_counters = [ (-1, 0, []) for _ in range(cores) ]
	for bucket, (core, counter) in enumerate(zip(lut, lut_counters)):
		core_counters[core] = (core, core_counters[core][1] + counter, core_counters[core][2] + [(bucket, counter)])
	return core_counters

def print_distribution(cores_counters):
	for idx, (bucket, counters) in enumerate(cores_counters):
		core_pkts = sum(counters)
		sorted_counters = sorted(counters, reverse=True)
		n = chunks_size = 10

		n_less_than_1_percent_counters = 0
		percent_counters = []

		for counter in sorted_counters:
			percent = float(counter) * 100.0 / core_pkts
			if percent < 1:
				n_less_than_1_percent_counters += 1
			else:
				percent_counters.append(f'{percent:<6.2f}')

		if n_less_than_1_percent_counters > 0:
			percent_counters.append(f'[ {n_less_than_1_percent_counters} with < 1% ]')

		chunks = [ percent_counters[i:i + chunks_size] for i in range(0, len(percent_counters), chunks_size) ]

		print(f'core     {idx}')
		print(f'pkts     {core_pkts}')

		for idx, chunk in enumerate(chunks):
			pchunk = ' '.join(chunk)

			if idx == 0:
				print(f'bucket % {pchunk}')
			else:
				print(f'         {pchunk}')
		print()

def get_lut_counters_partitioned(lut_counter_from_pcap, pcap_partitions):
	with Pool(processes=len(pcap_partitions)) as pool:
		return pool.map(lut_counter_from_pcap, pcap_partitions)

def group_core_counters(core_counters):
	pkts = 0
	for core_stats in core_counters:
		pkts += core_stats[1]
	avg = pkts / float(len(core_counters))

	groups = { 'pkts': pkts, 'avg': avg, 'underloaded': [], 'overloaded': [] }

	for core_stats in core_counters:
		if core_stats[1] > avg:
			groups['overloaded'].append(core_stats)
		else:
			groups['underloaded'].append(core_stats)

	return groups

def sort_groups(groups):
	groups['underloaded'] = sorted(groups['underloaded'], key=lambda tup:tup[1])

	for core_idx in range(len(groups['underloaded'])):
		core_stats = groups['underloaded'][core_idx]
		groups['underloaded'][core_idx] = (core_stats[0], core_stats[1], sorted(core_stats[2], key=lambda tup:tup[1]))

	groups['overloaded'] = sorted(groups['overloaded'], key=lambda tup:tup[1], reverse=True)

	for core_idx in range(len(groups['overloaded'])):
		core_stats = groups['overloaded'][core_idx]
		groups['overloaded'][core_idx] = (core_stats[0], core_stats[1], sorted(core_stats[2], key=lambda tup:tup[1], reverse=True))

	return groups

def balance(groups):
	if len(groups['overloaded']) == 0:
		return False, groups

	balance_effect = False

	overloaded_idx = 0
	while overloaded_idx < len(groups['overloaded']):
		overloaded_pkts = groups['overloaded'][overloaded_idx][1]
		change = False

		for overloaded_bucket_idx in range(len(groups['overloaded'][overloaded_idx][2])):
			overloaded_bucket      = groups['overloaded'][overloaded_idx][2][overloaded_bucket_idx]
			overloaded_bucket_pkts = overloaded_bucket[1]

			for underloaded_idx in range(len(groups['underloaded'])):
				underloaded_pkts        = groups['underloaded'][underloaded_idx][1]
				underloaded_bucket_pkts = groups['underloaded'][underloaded_idx][2][0][1]

				if underloaded_pkts + overloaded_bucket_pkts > groups['avg']:
					continue

				groups['underloaded'][underloaded_idx] = (
					groups['underloaded'][underloaded_idx][0],
					groups['underloaded'][underloaded_idx][1] + overloaded_bucket_pkts,
					groups['underloaded'][underloaded_idx][2] + [ overloaded_bucket ]
				)

				groups['overloaded'][overloaded_idx] = (
					groups['overloaded'][overloaded_idx][0],
					groups['overloaded'][overloaded_idx][1] - overloaded_bucket_pkts,
					groups['overloaded'][overloaded_idx][2][:overloaded_bucket_idx] + groups['overloaded'][overloaded_idx][2][overloaded_bucket_idx+1:]
				)

				change = True
				balance_effect = True
				break

			if change:
				break

		if not change or (groups['overloaded'][overloaded_idx][1] - groups['avg']) / groups['avg'] < 0.01:
			overloaded_idx += 1

	return balance_effect, groups

def print_groups(groups):
	print()
	print(f'Packets {groups["pkts"]}')
	print(f'Average {groups["avg"]}')
	print('Underloaded')
	for core_stats in groups['underloaded']:
		print(f'  core    {core_stats[0]}')
		print(f'  pkts    {core_stats[1]}')
		print(f'  buckets {core_stats[2][:5]} {"..." if len(core_stats[2]) > 5 else ""}')
		print()

	print('Overloaded')
	for core_stats in groups['overloaded']:
		print(f'  core    {core_stats[0]}')
		print(f'  pkts    {core_stats[1]}')
		print(f'  buckets {core_stats[2][:5]} {"..." if len(core_stats[2]) > 5 else ""}')
		print()

def find_good_lut(cores, lut_counters):
	lut = [ i % cores for i in range(LUT_SIZE) ]
	core_counters = lut_counters_to_core_counters(cores, lut, lut_counters)
	
	groups = group_core_counters(core_counters)
	groups = sort_groups(groups)

	while True:
		change, groups = balance(groups)
		groups = group_core_counters(groups['underloaded'] + groups['overloaded'])
		groups = sort_groups(groups)

		if not change:
			break

	underloaded_idx = 0
	for overloaded_idx in range(len(groups['overloaded'])):
		while len(groups['overloaded'][overloaded_idx][2]) != 1:
			overloaded_pkts = groups['overloaded'][overloaded_idx][1]

			if underloaded_idx >= len(groups['underloaded']):
				break

			overloaded_bucket      = groups['overloaded'][overloaded_idx][2][-1]
			overloaded_bucket_pkts = overloaded_bucket[1]

			groups['underloaded'][underloaded_idx] = (
				groups['underloaded'][underloaded_idx][0],
				groups['underloaded'][underloaded_idx][1] + overloaded_bucket_pkts,
				groups['underloaded'][underloaded_idx][2] + [ overloaded_bucket ]
			)

			groups['overloaded'][overloaded_idx] = (
				groups['overloaded'][overloaded_idx][0],
				groups['overloaded'][overloaded_idx][1] - overloaded_bucket_pkts,
				groups['overloaded'][overloaded_idx][2][:-1]
			)

			underloaded_idx += 1

	groups = group_core_counters(groups['underloaded'] + groups['overloaded'])
	groups = sort_groups(groups)

	while True:
		change, groups = balance(groups)
		groups = group_core_counters(groups['underloaded'] + groups['overloaded'])
		groups = sort_groups(groups)

		if not change:
			break

	available_cores = [ core for core in range(cores) ]

	for core_id in range(len(groups['overloaded'])):
		pkts    = groups['overloaded'][core_id][1]
		buckets = groups['overloaded'][core_id][2]

		found = False
		for candidate in range(len(available_cores)):
			if available_cores[candidate] % 2 == 0:
				groups['overloaded'][core_id] = (available_cores[candidate], pkts, buckets)
				available_cores = available_cores[:candidate] + available_cores[candidate + 1:]
				found = True
				break

		if not found:
			groups['overloaded'][core_id] = (available_cores[0], pkts, buckets)
			available_cores = available_cores[1:]

	for core_id in range(len(groups['underloaded'])):
		pkts    = groups['underloaded'][core_id][1]
		buckets = groups['underloaded'][core_id][2]

		groups['underloaded'][core_id] = (available_cores[0], pkts, buckets)
		available_cores = available_cores[1:]		

	if CONFIG['verbose']: print_groups(groups)

	balanced_lut = [ -1 for x in range(LUT_SIZE) ]
	core_counters = groups['underloaded'] + groups['overloaded']

	for (core, _, buckets) in core_counters:
		for (bucket, _) in buckets:
			balanced_lut[bucket] = core

	for bucket in balanced_lut:
		assert(bucket != -1)

	return balanced_lut

def copy_key(key):
	for i, entry in enumerate(key):
		if i >= len(CONFIG['key']): CONFIG['key'].append(entry)
		else: CONFIG['key'][i] = entry

def run(key, pcap, _verbose=False):
	copy_key(key)
	CONFIG['verbose'] = _verbose

	pcap_partitions = partition_pcap(pcap)

	lut_counters_partitioned = get_lut_counters_partitioned(lut_counter_from_pcap, pcap_partitions)
	lut_counters = [ sum(lut_entry) for lut_entry in zip(*lut_counters_partitioned) ]

	luts = []
	for cores in range(2, MAX_CORES + 1):
		if CONFIG['verbose']: print(cores, "cores")
		lut = find_good_lut(cores, lut_counters)
		luts.append(lut)
	
	delete_partitions(pcap_partitions)
	
	return luts
