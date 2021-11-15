#!/usr/bin/python3

import argparse
import csv
import sys
import os
import glob
import itertools

from random import randint

from scapy.all import *
from scapy.utils import PcapWriter

from multiprocessing import Pool, cpu_count, current_process
from subprocess import call
from pathlib import Path
from math import ceil, floor

N_PACKETS = 10000

def format_ip(addr, subnet_sz):
    return f"{(addr >> 24) & 0xff}.{(addr >> 16) & 0xff}.{(addr >> 8) & 0xff}.{(addr >> 0) & 0xff}/{subnet_sz}"

def random_subnet(bits):
    mask = get_subnet_mask(bits)
    addr = random.randint(0,0xFFFFFFFF) & mask
    return addr

def get_subnet_mask(bits):
    mask = 0
    for i in range(bits):
        mask = (mask >> 1) | (1 << 31)
    return mask

def get_addr_mask(bits):
    mask = 0
    for i in range(bits):
        mask = (mask << 1) | 1
    return mask

def random_mac():
    return f"02:00:00:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}"

def random_ip(subnet_sz, subnet_addr=None):
    addr = random.randint(0,0xFFFFFFFF)

    if not subnet_addr:
        subnet_addr = random_subnet(subnet_sz)

    subnet_mask = get_subnet_mask(subnet_sz)
    addr_mask = get_addr_mask(32 - subnet_sz)

    addr = (addr & addr_mask) | (subnet_addr & subnet_mask)
    return socket.inet_ntoa(struct.pack('!L', addr))

def random_port():
    return random.randint(1,10000)

def generate_pkts(output, hh_prefix_sz):
    pktdump = PcapWriter(output, append=False, sync=True)
    subnet = random_subnet(hh_prefix_sz)

    print(f"HH subnet: {format_ip(subnet, hh_prefix_sz)}")

    for i in range(N_PACKETS):
        mac_src = random_mac()
        mac_dst = random_mac()

        ip_src = random_ip(hh_prefix_sz, subnet) if i % 2 == 0 else random_ip(hh_prefix_sz)
        ip_dst = random_ip(hh_prefix_sz)

        sport = random_port()
        dport = random_port()

        pkt = Ether(src=mac_src, dst=mac_dst)
        pkt = pkt/IP(src=ip_src, dst=ip_dst)
        pkt = pkt/UDP(sport=sport, dport=dport)

        # print(pkt.show(dump=True))

        pktdump.write(pkt)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--output',  help='output pcap', required=True)
    parser.add_argument('--sz', help='heavy hitter prefix size', type=int, required=True)

    args = parser.parse_args()

    output = Path(args.output)

    output_dir = output.parent
    output_filename = output.name

    assert(Path(output_dir).exists())

    generate_pkts(args.output, args.sz)
