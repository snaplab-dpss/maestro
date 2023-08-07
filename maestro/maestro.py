#!/usr/bin/env python3

import pathlib
import os
import glob
import re
import argparse
import subprocess
import sys

from time import perf_counter
from datetime import timedelta 

from colorama import Fore, Style

from tools import get_balanced_lut
from tools import build

def __print(nf, msg, color):
	print(color, end="")
	print(f"[{pathlib.Path(nf).stem}] ", end="")
	print(msg, end="")
	print(Style.RESET_ALL)

def log(nf, msg=""):
	__print(nf, msg, Fore.LIGHTBLUE_EX)

def error(nf, msg=""):
	__print(nf, msg, Fore.RED)

def run(args, stdout=sys.stdout, stderr=sys.stderr, **pargs):
	if stdout is None: stdout = subprocess.DEVNULL
	if stderr is None: stderr = subprocess.DEVNULL

	process = subprocess.run(args, stdout=stdout, stderr=stderr, **pargs)
	return process.returncode

# env vars
KLEE_DIR = os.getenv("KLEE_DIR")

MAESTRO_DIR = pathlib.Path(__file__).parent.absolute()

BUILD_DIR = f"{MAESTRO_DIR}/build/maestro"
BUILD_SYNTHESIZED_DIR = f"{MAESTRO_DIR}/build/synthesized"

KLEE_CALL_PATH_ANALYZER = f"{KLEE_DIR}/Release/bin/analyze-call-paths"
KLEE_BDD_TO_C           = f"{KLEE_DIR}/Release/bin/bdd-to-c"
RSS_CONFIG_FROM_LVA     = f"{BUILD_DIR}/rss-config-from-lvas"

CHOICE_SEQUENTIAL     = "seq"
CHOICE_SHARED_NOTHING = "sn"
CHOICE_LOCKS          = "locks"
CHOICE_TM             = "tm"

CHOICE_TO_BOILERPLATE = {
	CHOICE_SEQUENTIAL: build.BOILERPLATE_CHOICE_SQ,
	CHOICE_SHARED_NOTHING: build.BOILERPLATE_CHOICE_SN,
	CHOICE_LOCKS: build.BOILERPLATE_CHOICE_LOCKS,
	CHOICE_TM: build.BOILERPLATE_CHOICE_TM,
}

SYNTHESIZED       = f"{BUILD_SYNTHESIZED_DIR}/nf_process.gen.c"
SYNTHESIZED_XML   = f"{BUILD_SYNTHESIZED_DIR}/nf_process.gen.xml"
LVA               = f"{BUILD_DIR}/report.lva"
LVA_DEBUG         = f"{BUILD_DIR}/report.txt"
RSS_CONF          = f"{BUILD_DIR}/rss_conf.txt"
RSS_KEY_LEN       = 52

COMPATIBLE_OPTS = [ "ETH_RSS_NONFRAG_IPV4_TCP", "ETH_RSS_NONFRAG_IPV4_UDP" ]

def build_maestro(nf):
	retcode = run([ "make" ], cwd=MAESTRO_DIR, stdout=None)
	if retcode != 0:
		error(nf, "Failed Maestro compilation")
		exit(1)

def clean_maestro():
	run([ "make", "clean" ], cwd=MAESTRO_DIR)

def symbex(nf, rerun=False):
	call_paths_dir = f"{nf}/klee-last"
	skipped = True

	if not os.path.exists(call_paths_dir) or rerun:
		log(nf, "Running symbolic execution")
		run("rm -rf klee-*", shell=True, cwd=os.path.abspath(nf))
		code = run([ "make", "symbex" ], cwd=os.path.abspath(nf))
		skipped = False
		
		if code != 0:
			exit(1)

	assert os.path.exists(call_paths_dir)
	call_paths = glob.glob(f"{call_paths_dir}/*.call_path")
	call_paths.sort(key=lambda f: int(re.sub('\D', '', f)))

	return call_paths, skipped

def analyze_call_paths(nf, call_paths):
	log(nf, "Analyzing call paths")

	analyzer_args = [ os.path.abspath(cp) for cp in call_paths ]

	lva = open(LVA, mode="w")
	code = run([ KLEE_CALL_PATH_ANALYZER ] + analyzer_args, stdout=lva)
	
	if code != 0:
		exit(1)

	lva.close()

def rss_conf_from_lvas(nf):
	log(nf, "Finding RSS configuration")

	rss_conf = open(RSS_CONF, mode='w')
	code = run([ RSS_CONFIG_FROM_LVA, LVA ], stdout=rss_conf)
	rss_conf.close()

	return code == 0

def rss_conf_random(devices):
	rss_conf = open(RSS_CONF, mode='w')
	code = run([ RSS_CONFIG_FROM_LVA, "--rand", str(devices) ], stdout=rss_conf)
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

	if target == CHOICE_SEQUENTIAL:
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

	bdd_to_c_args = f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} -target={target} {' '.join(call_paths)}"

	code = run([ KLEE_BDD_TO_C ] + bdd_to_c_args.split(' '))
	
	if code != 0:
		exit(1)

	synthesized_file    = open(SYNTHESIZED, mode='r')
	synthesized_content = synthesized_file.read()
	synthesized_file.close()

	return synthesized_content

def stitch_synthesized_nf(synthesized_content):
	code = ""

	for content in synthesized_content:
		code += f"\n{content}"
	
	synthesized_file = open(SYNTHESIZED, mode='w')
	synthesized_file.write(code)
	synthesized_file.close()

def synthesize_balance_lut(keys, pcap, target):
	code = ""

	if target == CHOICE_SEQUENTIAL:
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

	makefile = open(f"{MAESTRO_DIR}/Makefile.nf", mode='w')
	makefile.write(MAKEFILE)
	makefile.close()

def setup(nf):
	global KLEE_DIR

	if not KLEE_DIR and os.getenv("KLEE_INCLUDE"):
		KLEE_DIR = f"{os.getenv('KLEE_INCLUDE')}/../"
	elif not KLEE_DIR:
		error(nf, "Missing KLEE_DIR env var. Exiting.")
		exit(1)

	run([ "rm", "-rf", BUILD_SYNTHESIZED_DIR ])
	run([ "mkdir", "-p", BUILD_DIR ])
	run([ "mkdir", "-p", BUILD_SYNTHESIZED_DIR ])

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parallelize a Vigor NF.')
	
	parser.add_argument(
		'nf',
		type=str,
		help='path to the NF',
	)
	
	parser.add_argument(
		'--target',
		help='implementation model target',
		choices=[ CHOICE_SEQUENTIAL, CHOICE_SHARED_NOTHING, CHOICE_LOCKS, CHOICE_TM ],
		default=CHOICE_SHARED_NOTHING
	)

	parser.add_argument(
		'--symbex',
		action='store_true',
		required=False,
		default=False,
		help='Rerun symbolic execution',
	)

	parser.add_argument(
		'--balance',
		type=str,
		required=False,
		help='pcap used to balance LUT'
	)

	parser.add_argument(
		'--out',
		type=str,
		required=True,
		help='Output file',
	)

	args = parser.parse_args()
	args.nf = os.path.abspath(args.nf)

	if args.balance and not os.path.exists(args.balance):
		error(args.nf, f"Error: no such file or directory \"{args.balance}\"")

	setup(args.nf)
	build_maestro(args.nf)

	t_start = perf_counter()

	call_paths, skipped_symbex = symbex(args.nf, rerun=args.symbex)
	t_symbex = perf_counter()

	if args.target != CHOICE_SEQUENTIAL:
		analyze_call_paths(args.nf, call_paths)
		t_analyze_call_paths = perf_counter()

		if args.target == CHOICE_SHARED_NOTHING:
			success = rss_conf_from_lvas(args.nf)
			if not success:
				error("Unable to synthesize a parallel implementation using a shared nothing model.")
		else:
			success = rss_conf_random(2) # TODO devices
			assert(success)

		t_rss_conf = perf_counter()

	log(args.nf, "Synthesizing")
	synthesized_content = []

	rss_conf_code, keys = synthesize_rss_conf(args.target)
	synthesized_content.append(rss_conf_code)

	synthesized_nf = synthesize_nf(args.nf, call_paths, args.target)
	synthesized_content.append(synthesized_nf)

	balance_lut_code = synthesize_balance_lut(keys, args.balance, args.target)
	synthesized_content.append(balance_lut_code)

	stitch_synthesized_nf(synthesized_content)
	complete_impl_fname = build.build(CHOICE_TO_BOILERPLATE[args.target], SYNTHESIZED, args.nf)

	run([ "cp", complete_impl_fname, args.out ])

	t_synthesize = perf_counter()
	t_end = t_synthesize

	log(args.nf, "================ REPORT ================")
	if not skipped_symbex:
		log(args.nf, f"Symbolic execution  {timedelta(seconds=(t_symbex - t_start))}")
	if args.target != CHOICE_SEQUENTIAL:
		log(args.nf, f"Call path analysis  {timedelta(seconds=(t_analyze_call_paths - t_symbex))}")
		log(args.nf, f"Solver              {timedelta(seconds=(t_rss_conf - t_analyze_call_paths))}")
		log(args.nf, f"Synthesize          {timedelta(seconds=(t_synthesize - t_rss_conf))}")
	else:
		log(args.nf, f"Synthesize          {timedelta(seconds=(t_synthesize - t_symbex))}")
	log(args.nf, f"Total               {timedelta(seconds=(t_end - t_start))}")
	log(args.nf, "========================================")

