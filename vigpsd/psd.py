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

def random_mac():
    return f"02:00:00:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}:{randint(0, 0xff):02x}"

def random_ip():
    addr = random.randint(0,0xFFFFFFFF)
    return socket.inet_ntoa(struct.pack('!L', addr))

def random_port():
    return random.randint(1,10000)

def generate_pkts(output):
    pktdump = PcapWriter(output, append=False, sync=True)

    src = random_ip()
    port = 0

    print(f"Port scanning source: {src}")

    for i in range(N_PACKETS):
        mac_src = random_mac()
        mac_dst = random_mac()

        if i % 5 == 0:
            ip_src = src
            dport = port    
            port += 1
        else:
            ip_src = src if i % 5 == 0 else random_ip()
            dport = random_port()

        ip_dst = random_ip()
        sport = random_port()

        pkt = Ether(src=mac_src, dst=mac_dst)
        pkt = pkt/IP(src=ip_src, dst=ip_dst)
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
