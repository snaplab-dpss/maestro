#!/usr/bin/python3

import sys
import pathlib
import os
import glob
import re
import argparse

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

BOILERPLATE = {
	CHOICE_SEQUENTIAL:		f"{MAESTRO_DIR}/boilerplate/sequential.c",
	CHOICE_SHARED_NOTHING:	f"{MAESTRO_DIR}/boilerplate/shared-nothing.c",
	CHOICE_LOCKS:			f"{MAESTRO_DIR}/boilerplate/locks.c",
}

SYNTHESIZED 	 = f"{BUILD_DIR}/nf_process.gen.c"
SYNTHESIZED_XML  = f"{BUILD_DIR}/nf_process.gen.xml"
PARALLEL_NF 	 = f"{BUILD_DIR}/nf.c"
LVA 			 = f"{BUILD_DIR}/report.lva"
LVA_DEBUG 		 = f"{BUILD_DIR}/report.txt"
RSS_CONF 		 = f"{BUILD_DIR}/rss_conf.txt"
RSS_KEY_LEN		 = 52

def build_maestro():
	os.system("make maestro > /dev/null")

def symbex(nf):
	os.system(f"cd {nf}; make symbex")

	call_paths = glob.glob(f"{nf}/klee-last/*.call_path")
	call_paths.sort(key=lambda f: int(re.sub('\D', '', f)))

	return call_paths

def analyze_call_paths(nf, call_paths):
	analyze 		= f"{KLEE_DIR}/build/bin/analyse-libvig-call-paths"
	analyze_args	= ' '.join(call_paths)

	os.system(f"{analyze} {analyze_args} > {LVA}")

def rss_conf_from_lvas():
	rss_conf_from_lva 		= f"{BUILD_DIR}/rss-config-from-lvas"
	rss_conf_from_lva_args	= f"{BUILD_DIR}/report.lva"

	code = os.system(f"{rss_conf_from_lva} {rss_conf_from_lva_args} > {RSS_CONF}")
	return code == 0

def rss_conf_random(devices):
	rss_conf_from_lva 		= f"{BUILD_DIR}/rss-config-from-lvas"

	code = os.system(f"{rss_conf_from_lva} --rand {devices} > {RSS_CONF}")
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
	if target == CHOICE_SEQUENTIAL:	return ""

	f = open(RSS_CONF, 'r')
	rss_conf = f.read()
	f.close()

	rss_conf = rss_conf.split('\n')
	rss_conf = list(filter(len, rss_conf))
	
	devices = int(len(rss_conf) / 2)
	confs 	= []
	code = ""

	assert(devices)

	for device in range(devices):
		opts = rss_conf[device * 2].split(' ')
		key	 = [ int(v) for v in rss_conf[device * 2 + 1].split(' ') ]

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
	return code

def synthesize_nf(nf, call_paths, target):
	assert(call_paths)

	bdd_to_c 		= f"{KLEE_DIR}/build/bin/bdd-to-c"
	bdd_to_c_args	= f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} -target={target} {' '.join(call_paths)}"

	os.system(f"{bdd_to_c} {bdd_to_c_args}")

	synthesized_file    = open(SYNTHESIZED, mode='r')
	synthesized_content = synthesized_file.read()
	synthesized_file.close()

	return synthesized_content

def stitch_synthesized_nf(synthesized_content, target):
	assert(target in BOILERPLATE)

	boilerplate_file    = open(BOILERPLATE[target], mode='r')
	boilerplate_content = boilerplate_file.read()
	boilerplate_file.close()

	parallel_content = f"{boilerplate_content}\n{synthesized_content}\n\n"

	parallel_file = open(PARALLEL_NF, mode='w')
	parallel_file.write(parallel_content)
	parallel_file.close()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parallelize a Vigor NF.')
	
	parser.add_argument('nf', type=str, help='path to the NF')
	parser.add_argument('--target', 											\
		help='implementation model target', 									\
		choices = [ CHOICE_SEQUENTIAL, CHOICE_SHARED_NOTHING, CHOICE_LOCKS ],	\
		default=CHOICE_SHARED_NOTHING)

	args = parser.parse_args()

	build_maestro()
	call_paths = symbex(args.nf)
	analyze_call_paths(args.nf, call_paths)

	if args.target == CHOICE_SHARED_NOTHING:
		success = rss_conf_from_lvas()
		if not success:
			print("Unable to synthesize a parallel implementation using a shared nothing model.")
			exit(1)
	elif args.target == CHOICE_LOCKS:
		success = rss_conf_random(2) # TODO devices
		assert(success)

	synthesized_nf = synthesize_nf(args.nf, call_paths, args.target)

	rss_conf_code = synthesize_rss_conf(args.target)
	synthesized_content = f"{rss_conf_code}\n{synthesized_nf}"

	stitch_synthesized_nf(synthesized_content, args.target)
