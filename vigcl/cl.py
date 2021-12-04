#!/usr/bin/python3

import argparse
import csv
import sys
import os
import glob
import itertools

from random import randint, choice

from scapy.all import *
from scapy.utils import PcapWriter

from multiprocessing import Pool, cpu_count, current_process
from subprocess import call
from pathlib import Path
from math import ceil, floor

N_PACKETS = 10000
N_SOURCES = 100

def random_mac():
    return f"02:00:00:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}"

def random_ip():
    addr = random.randint(0,0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack('!L', addr))

def random_port():
    return random.randint(1,10000)

def generate_pkts(output):
    pktdump = PcapWriter(output, append=False, sync=True)

    mac_src = random_mac()
    mac_dst = random_mac()

    dst_ip = random_ip()
    dport = random_port()

    sources = [ (random_ip(), random_port()) for x in range(N_SOURCES) ]
    greedy = random.choice(sources)

    print(f"Greedy client: {greedy[0]}")

    for i in range(N_PACKETS):
        src_ip, sport = sources[i % N_SOURCES]
      
        if src_ip == greedy[0]:
            sport = random_port()

        pkt = Ether(src=mac_src, dst=mac_dst)
        pkt = pkt/IP(src=src_ip, dst=dst_ip)
        pkt = pkt/UDP(sport=sport, dport=dport)

        pktdump.write(pkt)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument('--output',  help='output pcap', required=True)

    args = parser.parse_args()

    output = Path(args.output)

    output_dir = output.parent
    output_filename = output.name

    assert(Path(output_dir).exists())

    generate_pkts(args.output)
