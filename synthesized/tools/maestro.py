#!/usr/bin/python3

import pathlib
import os
import glob
import re
import argparse
import subprocess

from time import perf_counter
from datetime import timedelta 

import get_balanced_lut
import build

# env vars
KLEE_DIR = os.getenv("KLEE_DIR")

if not KLEE_DIR and os.getenv("KLEE_INCLUDE"):
	KLEE_DIR = f"{os.getenv('KLEE_INCLUDE')}/../"

elif not KLEE_DIR:
	print("Missing KLEE_DIR env var. Exiting.")
	exit(1)

SYNTHESIZED_DIR=pathlib.Path(__file__).parent.parent.absolute()

BUILD_DIR = f"{SYNTHESIZED_DIR}/build/maestro"
BUILD_SYNTHESIZED_DIR = f"{SYNTHESIZED_DIR}/build/synthesized"

subprocess.call([ "rm", "-rf", BUILD_SYNTHESIZED_DIR ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

subprocess.call([ "mkdir", "-p", BUILD_DIR ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.call([ "mkdir", "-p", BUILD_SYNTHESIZED_DIR ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

CHOICE_SEQUENTIAL     = "seq"
CHOICE_SHARED_NOTHING = "sn"
CHOICE_LOCKS          = "locks"
CHOICE_TM             = "tm"
CHOICE_CPH            = "cph"

CHOICE_TO_BOILERPLATE = {
	CHOICE_SEQUENTIAL: build.BOILERPLATE_CHOICE_SQ,
	CHOICE_SHARED_NOTHING: build.BOILERPLATE_CHOICE_SN,
	CHOICE_LOCKS: build.BOILERPLATE_CHOICE_LOCKS,
	CHOICE_TM: build.BOILERPLATE_CHOICE_TM,
	CHOICE_CPH: build.BOILERPLATE_CHOICE_CALL_PATH_HITTER,
}

SYNTHESIZED       = f"{BUILD_SYNTHESIZED_DIR}/nf_process.gen.c"
SYNTHESIZED_XML   = f"{BUILD_SYNTHESIZED_DIR}/nf_process.gen.xml"
LVA               = f"{BUILD_DIR}/report.lva"
LVA_DEBUG         = f"{BUILD_DIR}/report.txt"
RSS_CONF          = f"{BUILD_DIR}/rss_conf.txt"
RSS_KEY_LEN       = 52

COMPATIBLE_OPTS = [ "ETH_RSS_NONFRAG_IPV4_TCP", "ETH_RSS_NONFRAG_IPV4_UDP" ]

def error():
	print("Exiting...")
	exit(1)

def build_maestro():
	subprocess.call([ "make", "maestro" ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def clean_maestro():
	subprocess.call([ "make", "clean-maestro" ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  
def symbex(nf):
	subprocess.Popen("rm -rf klee-*", shell=True, cwd=os.path.abspath(nf), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	code = subprocess.call([ "make", "symbex" ], cwd=os.path.abspath(nf), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	if code != 0: error()

	call_paths = glob.glob(f"{nf}/klee-last/*.call_path")
	call_paths.sort(key=lambda f: int(re.sub('\D', '', f)))

	return call_paths

def analyze_call_paths(nf, call_paths):
	analyze 		= f"{KLEE_DIR}/Release/bin/analyse-libvig-call-paths"
	analyze_args	= [ os.path.abspath(cp) for cp in call_paths ]

	lva = open(LVA, mode="w")
	code = subprocess.call([ analyze ] + analyze_args, stdout=lva)
	
	if code != 0: error()
	lva.close()

def rss_conf_from_lvas():
	rss_conf_from_lva = f"{BUILD_DIR}/rss-config-from-lvas"
	rss_conf_from_lva_arg = f"{BUILD_DIR}/report.lva"

	rss_conf = open(RSS_CONF, mode='w')
	code = subprocess.call([ rss_conf_from_lva, rss_conf_from_lva_arg ], stdout=rss_conf)
	rss_conf.close()

	return code == 0

def rss_conf_random(devices):
	rss_conf_from_lva = f"{BUILD_DIR}/rss-config-from-lvas"
	
	rss_conf = open(RSS_CONF, mode='w')
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

	if target == CHOICE_SEQUENTIAL or target == CHOICE_CPH:
		return (code, keys)

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
		opts  	 = list(filter(lambda opt: opt in COMPATIBLE_OPTS, conf[1]))

		code += f"  {{\n"
		code += f"    .rss_key = {var_name},\n"
		code += f"    .rss_key_len = RSS_HASH_KEY_LENGTH,\n"
		code += f"    .rss_hf = {' | '.join(opts)}\n"
		code += f"  }}"
		if iconf != len(confs) - 1: code += ",\n"

	code += f"\n}};"
	return (code, keys)

def synthesize_nf(nf, call_paths, target):
	assert(call_paths)

	bdd_to_c      = f"{KLEE_DIR}/Release/bin/bdd-to-c"
	bdd_to_c_args	= f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} -target={target} {' '.join(call_paths)}"

	code = subprocess.call([ bdd_to_c ] + bdd_to_c_args.split(' '))
	
	if code != 0: error()

	synthesized_file    = open(SYNTHESIZED, mode='r')
	synthesized_content = synthesized_file.read()
	synthesized_file.close()

	return synthesized_content

def stitch_synthesized_nf(synthesized_content, target):
	code = ""

	for content in synthesized_content:
		code += f"\n{content}"
	
	synthesized_file = open(SYNTHESIZED, mode='w')
	synthesized_file.write(code)
	synthesized_file.close()

def synthesize_balance_lut(keys, pcap, target):
	code = ""

	if target == CHOICE_SEQUENTIAL or target == CHOICE_CPH:
		return code

	code += "void init_retas() {\n"                                \
			"  for (unsigned i = 0; i < MAX_NUM_DEVICES; i++) {\n" \
			"    retas_per_device[i].set = false;\n"               \
			"  }\n"

	if not pcap:
		code += "}"
		return code

	for ikey, key in enumerate(keys):
		print(f"Balancing LUT for key {ikey}")
		lut = get_balanced_lut.run(key, pcap, True)

		code += "\n"
		code += f"  retas_per_device[{ikey}].set = true;"

		for j, lut_core in enumerate(lut):
			code += "\n"

			for k, bucket in enumerate(lut_core):
				code += f"  retas_per_device[{ikey}].tables[{j}][{k}] = {bucket};\n"
	
	code += "}"

	return code

def bundle_everything(nf):
	seq_nf_files = []
	seq_nf_files += glob.glob(f"{nf}/*.c")
	seq_nf_files += glob.glob(f"{nf}/*.h")
	seq_nf_files += glob.glob(f"{nf}/*.py")
	seq_nf_files += glob.glob(f"{nf}/*.ml")

	MAKEFILE = ""
	for f in seq_nf_files:
		if len(MAKEFILE) == 0:
			MAKEFILE += f"SEQ_NF_FILES_ABS_PATH := {os.path.abspath(f)}\n"
			MAKEFILE += f"SEQ_NF_FILES_BASE := {os.path.basename(f)}\n"
		else:
			MAKEFILE += f"SEQ_NF_FILES_ABS_PATH += {os.path.abspath(f)}\n"
			MAKEFILE += f"SEQ_NF_FILES_BASE += {os.path.basename(f)}\n"

	MAKEFILE += f"\ninclude {os.path.abspath(nf)}/Makefile\n"

	makefile = open(f"{SYNTHESIZED_DIR}/Makefile.nf", mode='w')
	makefile.write(MAKEFILE)
	makefile.close()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parallelize a Vigor NF.')
	
	parser.add_argument('nf', type=str, help='path to the NF')
	parser.add_argument('--target', 													  \
		help='implementation model target', 											\
		choices=[ CHOICE_SEQUENTIAL, CHOICE_SHARED_NOTHING, CHOICE_LOCKS, CHOICE_TM, CHOICE_CPH ],	\
		default=CHOICE_SHARED_NOTHING)
	parser.add_argument('--randomize', type=str, help='randomize RSS keys')
	parser.add_argument('--balance', type=str, help='pcap used to balance LUT')

	args = parser.parse_args()
	args.nf = os.path.abspath(args.nf)

	print("[*] Building maestro")
	build_maestro()

	t_start = perf_counter()

	print("[*] Running symbolic execution")
	call_paths = symbex(args.nf)
	t_symbex = perf_counter()

	if args.target != CHOICE_SEQUENTIAL and args.target != CHOICE_CPH:
		print("[*] Analyzing call paths")
		analyze_call_paths(args.nf, call_paths)
		t_analyze_call_paths = perf_counter()

		print("[*] Finding RSS configuration")
		if not args.randomize and args.target == CHOICE_SHARED_NOTHING:
			success = rss_conf_from_lvas()
			if not success:
				print("Unable to synthesize a parallel implementation using a shared nothing model.")
				exit(1)
		else:
			success = rss_conf_random(2) # TODO devices
			assert(success)

		t_rss_conf = perf_counter()

	print("[*] Synthesizing")
	synthesized_content = []

	rss_conf_code, keys = synthesize_rss_conf(args.target)
	synthesized_content.append(rss_conf_code)

	synthesized_nf = synthesize_nf(args.nf, call_paths, args.target)
	synthesized_content.append(synthesized_nf)

	balance_lut_code = synthesize_balance_lut(keys, args.balance, args.target)
	synthesized_content.append(balance_lut_code)

	stitch_synthesized_nf(synthesized_content, args.target)
	build.build(CHOICE_TO_BOILERPLATE[args.target], SYNTHESIZED, args.nf)

	t_synthesize = perf_counter()
	t_end = t_synthesize

	print("[*] Cleaning")
	clean_maestro()

	print()
	print("================ REPORT ================")
	print(f"Symbolic execution  {timedelta(seconds=(t_symbex - t_start))}")
	if args.target != CHOICE_SEQUENTIAL and args.target != CHOICE_CPH:
		print(f"Call path analysis  {timedelta(seconds=(t_analyze_call_paths - t_symbex))}")
		print(f"Solver              {timedelta(seconds=(t_rss_conf - t_analyze_call_paths))}")
		print(f"Synthesize          {timedelta(seconds=(t_synthesize - t_rss_conf))}")
	else:
		print(f"Synthesize          {timedelta(seconds=(t_synthesize - t_symbex))}")
	print(f"Total               {timedelta(seconds=(t_end - t_start))}")
	print("========================================")

