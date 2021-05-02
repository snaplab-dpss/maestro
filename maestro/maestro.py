#!/usr/bin/python3

import sys
import pathlib
import os
import glob
import re
import argparse
import subprocess

from time import perf_counter
from datetime import timedelta 

import get_balanced_lut

# env vars
KLEE_DIR = os.getenv("KLEE_DIR")

if not KLEE_DIR and os.getenv("KLEE_INCLUDE"):
	KLEE_DIR = f"{os.getenv('KLEE_INCLUDE')}/../"

elif not KLEE_DIR:
	print("Missing KLEE_DIR env var. Exiting.")
	exit(1)

MAESTRO_DIR=pathlib.Path(__file__).parent.absolute()

BUILD_DIR = f"{MAESTRO_DIR}/build/maestro"

CHOICE_SEQUENTIAL 		= "seq"
CHOICE_SHARED_NOTHING	= "sn"
CHOICE_LOCKS	 		= "locks"
CHOICE_TM				= "tm"

BOILERPLATE = {
	CHOICE_SEQUENTIAL:		f"{MAESTRO_DIR}/boilerplate/sequential.c",
	CHOICE_SHARED_NOTHING:	f"{MAESTRO_DIR}/boilerplate/shared-nothing.c",
	CHOICE_LOCKS:			f"{MAESTRO_DIR}/boilerplate/locks.c",
	CHOICE_TM:				f"{MAESTRO_DIR}/boilerplate/tm.c",
}

SYNTHESIZED 	 = f"{BUILD_DIR}/nf_process.gen.c"
SYNTHESIZED_XML  = f"{BUILD_DIR}/nf_process.gen.xml"
FINAL_CODE 	 	 = f"{BUILD_DIR}/nf.c"
LVA 			 = f"{BUILD_DIR}/report.lva"
LVA_DEBUG 		 = f"{BUILD_DIR}/report.txt"
RSS_CONF 		 = f"{BUILD_DIR}/rss_conf.txt"
RSS_KEY_LEN		 = 52

RETA_MARKER		 = "/*@INIT-RETAS@*/"

def error(verbose):
	if not verbose:
		print("\nOh-oh something went wrong. Use '-v' to gather clues.")
	print("Exiting...")
	exit(1)

def build_maestro():
	subprocess.call([ "make", "maestro" ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	
def symbex(nf, verbose):
	if not verbose:
		code = subprocess.call([ "make", "symbex" ], cwd=os.path.abspath(nf), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	else:
		code = subprocess.call([ "make", "symbex" ], cwd=os.path.abspath(nf))

	if code != 0: error(verbose)

	call_paths = glob.glob(f"{nf}/klee-last/*.call_path")
	call_paths.sort(key=lambda f: int(re.sub('\D', '', f)))

	return call_paths

def analyze_call_paths(nf, call_paths, verbose):
	analyze 		= f"{KLEE_DIR}/build/bin/analyse-libvig-call-paths"
	analyze_args	= [ os.path.abspath(cp) for cp in call_paths ]

	lva = open(LVA, mode="w")
	if not verbose:
		code = subprocess.call([ analyze ] + analyze_args, stdout=lva, stderr=subprocess.DEVNULL)
	else:
		code = subprocess.call([ analyze ] + analyze_args, stdout=lva)
	
	if code != 0: error(verbose)
	lva.close()

def rss_conf_from_lvas(verbose):
	rss_conf_from_lva 		= f"{BUILD_DIR}/rss-config-from-lvas"
	rss_conf_from_lva_arg 	= f"{BUILD_DIR}/report.lva"

	rss_conf = open(RSS_CONF, mode='w')
	if not verbose:
		code = subprocess.call([ rss_conf_from_lva, rss_conf_from_lva_arg ], stdout=rss_conf, stderr=subprocess.DEVNULL)
	else:
		code = subprocess.call([ rss_conf_from_lva, rss_conf_from_lva_arg ], stdout=rss_conf)
	rss_conf.close()

	return code == 0

def rss_conf_random(devices, verbose):
	rss_conf_from_lva 		= f"{BUILD_DIR}/rss-config-from-lvas"
	
	rss_conf = open(RSS_CONF, mode='w')
	if not verbose:
		code = subprocess.call([ rss_conf_from_lva, "--rand", str(devices) ], stdout=rss_conf, stderr=subprocess.DEVNULL)
	else:
		code = subprocess.call([ rss_conf_from_lva, "--rand", str(devices) ], stdout=rss_conf)
	rss_conf.close()

	return code == 0

def code_key(key_values, ikey):
	assert(len(key_values) == RSS_KEY_LEN)
	var_name = f"hash_key_{ikey}"
	code = f"uint8_t {var_name}[RSS_HASH_KEY_LENGTH] = {{"

	for i in range(RSS_KEY_LEN):
		if i % 8 == 0: code += '\n  '
		code += f"{hex(key_values[i])}"
		if i != RSS_KEY_LEN - 1: code += ", "
	code += f"\n}};\n"
	return (var_name, code)

def synthesize_rss_conf(target):
	code = ""
	keys = []
	if target == CHOICE_SEQUENTIAL:	return ((None, code), keys)

	f = open(RSS_CONF, 'r')
	rss_conf = f.read()
	f.close()

	rss_conf = rss_conf.split('\n')
	rss_conf = list(filter(len, rss_conf))
	
	devices = int(len(rss_conf) / 2)
	confs 	= []


	assert(devices)

	for device in range(devices):
		opts = rss_conf[device * 2].split(' ')
		key	 = [ int(v) for v in rss_conf[device * 2 + 1].split(' ') ]
		keys.append(key)

		var_name, key_code = code_key(key, device)
		code += key_code

		confs.append((var_name, opts))
	
	code += f"\nstruct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {{\n"
	for iconf, conf in enumerate(confs):
		var_name = conf[0]
		opts	 = conf[1]

		code += f"  {{\n"
		code += f"    .rss_key = {var_name},\n"
		code += f"    .rss_key_len = RSS_HASH_KEY_LENGTH,\n"
		code += f"    .rss_hf = {' | '.join(opts)}\n"
		code += f"  }}"
		if iconf != len(confs) - 1: code += ",\n"

	code += f"\n}};"
	return (None, code), keys

def synthesize_nf(nf, call_paths, target, verbose):
	assert(call_paths)

	bdd_to_c 		= f"{KLEE_DIR}/build/bin/bdd-to-c"
	bdd_to_c_args	= f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} -target={target} {' '.join(call_paths)}"

	if not verbose:
		code = subprocess.call([ bdd_to_c ] + bdd_to_c_args.split(' '), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	else:
		code = subprocess.call([ bdd_to_c ] + bdd_to_c_args.split(' '))
	
	if code != 0: error(verbose)

	synthesized_file    = open(SYNTHESIZED, mode='r')
	synthesized_content = synthesized_file.read()
	synthesized_file.close()

	return (None, synthesized_content)

def stitch_synthesized_nf(synthesized_content, target):
	assert(target in BOILERPLATE)

	boilerplate_file    = open(BOILERPLATE[target], mode='r')
	boilerplate_content = boilerplate_file.read()
	boilerplate_file.close()

	code = boilerplate_content
	for marker, content in synthesized_content:
		if not marker: code += f"\n{content}"
		else: code = code.replace(marker, content)

	final_code_file = open(FINAL_CODE, mode='w')
	final_code_file.write(code)
	final_code_file.close()

def synthesize_balance_lut(keys, pcap, target, verbose):
	code = ""
	if target == CHOICE_SEQUENTIAL or not pcap:	return (None, code)

	for ikey, key in enumerate(keys):
		if verbose: print(f"Balancing LUT for key {ikey}")
		lut = get_balanced_lut.run(key, pcap, verbose)

		code += "\n"
		code += f"  retas_per_device[{ikey}].set = true;"

		for j, lut_core in enumerate(lut):
			code += "\n"

			for k, bucket in enumerate(lut_core):
				code += f"  retas_per_device[{ikey}].tables[{j}][{k}] = {bucket};\n"

	return (RETA_MARKER, code)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parallelize a Vigor NF.')
	
	parser.add_argument('nf', type=str, help='path to the NF')
	parser.add_argument('-v', action='store_true', help='verbose')
	parser.add_argument('--target', 													\
		help='implementation model target', 											\
		choices=[ CHOICE_SEQUENTIAL, CHOICE_SHARED_NOTHING, CHOICE_LOCKS, CHOICE_TM ],	\
		default=CHOICE_SHARED_NOTHING)
	parser.add_argument('--balance', type=str, help='pcap used to balance LUT')

	args = parser.parse_args()

	print("[1/5] Building maestro")
	build_maestro()

	t_start = perf_counter()

	print("[2/5] Running symbolic execution")
	call_paths = symbex(args.nf, args.v)
	t_symbex = perf_counter()

	print("[3/5] Analyzing call paths")
	analyze_call_paths(args.nf, call_paths, args.v)
	t_analyze_call_paths = perf_counter()

	print("[4/5] Finding RSS configuration")
	if args.target == CHOICE_SHARED_NOTHING:
		success = rss_conf_from_lvas(args.v)
		if not success:
			print("Unable to synthesize a parallel implementation using a shared nothing model.")
			exit(1)
	elif args.target == CHOICE_LOCKS:
		success = rss_conf_random(2, args.v) # TODO devices
		assert(success)

	t_rss_conf = perf_counter()

	print("[5/5] Synthesizing parallel implementation")
	synthesized_content = []

	rss_conf_code, keys = synthesize_rss_conf(args.target)
	synthesized_content.append(rss_conf_code)

	synthesized_nf = synthesize_nf(args.nf, call_paths, args.target, args.v)
	synthesized_content.append(synthesized_nf)

	balance_lut_code = synthesize_balance_lut(keys, args.balance, args.target, args.v)
	synthesized_content.append(balance_lut_code)

	stitch_synthesized_nf(synthesized_content, args.target)
	t_synthesize = perf_counter()
	t_end = t_synthesize

	print()
	print("================ REPORT ================")
	print(f"Symbolic execution  {timedelta(seconds=(t_symbex - t_start))}")
	print(f"Call path analysis  {timedelta(seconds=(t_analyze_call_paths - t_symbex))}")
	print(f"Solver              {timedelta(seconds=(t_rss_conf - t_analyze_call_paths))}")
	print(f"Synthesize          {timedelta(seconds=(t_synthesize - t_rss_conf))}")
	print(f"Total               {timedelta(seconds=(t_end - t_start))}")
	print("========================================")