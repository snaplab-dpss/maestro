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

BOILERPLATE = f"{MAESTRO_DIR}/boilerplate.c"
SYNTHESIZED = f"{BUILD_DIR}/nf.process.gen.c"
SYNTHESIZED_XML = f"{BUILD_DIR}/nf.process.gen.xml"
PARALLEL_NF = f"{BUILD_DIR}/nf.c"
LVA = f"{BUILD_DIR}/report.lva"
LVA_DEBUG = f"{BUILD_DIR}/report.txt"

def symbex(nf):
	#os.system(f"cd {nf}; make symbex")

	call_paths = glob.glob(f"{nf}/klee-last/*.call_path")
	call_paths.sort(key=lambda f: int(re.sub('\D', '', f)))

	return call_paths

def synthesize_nf(nf, call_paths):
	assert(call_paths)

	BDD_TO_C_CODE = f"{KLEE_DIR}/build/bin/bdd-to-C-code"
	BDD_TO_C_CODE_ARGS = f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} {' '.join(call_paths)}"

	os.system(f"{BDD_TO_C_CODE} {BDD_TO_C_CODE_ARGS}")

def stitch_synthesized_nf():
	boilerplate_file = open(BOILERPLATE, mode='r')
	boilerplate_content = boilerplate_file.read()
	boilerplate_file.close()

	synthesized_file = open(SYNTHESIZED, mode='r')
	synthesized_content = synthesized_file.read()
	synthesized_file.close()

	parallel_content = f"{boilerplate_content}\n{synthesized_content}\n"

	parallel_file = open(PARALLEL_NF, mode='w')
	parallel_file.write(parallel_content)
	parallel_file.close()

def analyze_call_paths(nf, call_paths):
	ANALYZE = f"{KLEE_DIR}/build/bin/analyse-libvig-call-paths"
	ANALYZE_ARGS = ' '.join(call_paths)

	#os.system(f"{ANALYZE} {ANALYZE_ARGS} > {LVA} 2> {LVA_DEBUG}")
	os.system(f"{ANALYZE} {ANALYZE_ARGS} > {LVA}")

def rss_conf_from_lvas():
	RSS_CONF_FROM_LVA = f"{BUILD_DIR}/rss-config-from-lvas"
	RSS_CONF_FROM_LVA_ARGS = f"{BUILD_DIR}/report.lva"
	RSS_CONF_FROM_LVA_OUT = f"{BUILD_DIR}/rss_conf.txt"

	os.system(f"{RSS_CONF_FROM_LVA} {RSS_CONF_FROM_LVA_ARGS} > {RSS_CONF_FROM_LVA_OUT}")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parallelize a Vigor NF.')
	
	parser.add_argument('nf', type=str, help='path to the NF')
	parser.add_argument('--locks', help='use locking mechanisms')

	args = parser.parse_args()

	call_paths = symbex(args.nf)
	analyze_call_paths(args.nf, call_paths)
	rss_conf_from_lvas()
	#synthesize_nf(args.nf, call_paths)
	#stitch_synthesized_nf()