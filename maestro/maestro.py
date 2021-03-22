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

#BOILERPLATE = f"{MAESTRO_DIR}/boilerplate.c"
BOILERPLATE = f"{MAESTRO_DIR}/boilerplate/sequential.c"
SYNTHESIZED = f"{BUILD_DIR}/nf_process.gen.c"
SYNTHESIZED_XML = f"{BUILD_DIR}/nf_process.gen.xml"
PARALLEL_NF = f"{BUILD_DIR}/nf.c"
LVA = f"{BUILD_DIR}/report.lva"
LVA_DEBUG = f"{BUILD_DIR}/report.txt"

def symbex(nf):
	# os.system(f"cd {nf}; make symbex")

	call_paths = glob.glob(f"{nf}/klee-last/*.call_path")
	call_paths.sort(key=lambda f: int(re.sub('\D', '', f)))

	return call_paths

def analyze_call_paths(nf, call_paths):
	analyze 		= f"{KLEE_DIR}/build/bin/analyse-libvig-call-paths"
	analyze_args	= ' '.join(call_paths)

	# os.system(f"{analyze} {analyze_args} > {LVA} 2> {LVA_DEBUG}")
	os.system(f"{analyze} {analyze_args} > {LVA}")

def rss_conf_from_lvas():
	rss_conf_from_lva 		= f"{BUILD_DIR}/rss-config-from-lvas"
	rss_conf_from_lva_args	= f"{BUILD_DIR}/report.lva"
	rss_conf_from_lva_out	= f"{BUILD_DIR}/rss_conf.txt"

	code = os.system(f"{rss_conf_from_lva} {rss_conf_from_lva_args} > {rss_conf_from_lva_out}")
	return code == 0

def synthesize_nf(nf, call_paths, shared_nothing):
	assert(call_paths)

	bdd_to_c 		= f"{KLEE_DIR}/build/bin/bdd-to-c"
	bdd_to_c_args	= f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} {' '.join(call_paths)}"

	os.system(f"{bdd_to_c} {bdd_to_c_args}")

def stitch_synthesized_nf():
	boilerplate_file    = open(BOILERPLATE, mode='r')
	boilerplate_content = boilerplate_file.read()
	boilerplate_file.close()

	synthesized_file    = open(SYNTHESIZED, mode='r')
	synthesized_content = synthesized_file.read()
	synthesized_file.close()

	parallel_content = f"{boilerplate_content}\n{synthesized_content}\n"

	parallel_file = open(PARALLEL_NF, mode='w')
	parallel_file.write(parallel_content)
	parallel_file.close()

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Parallelize a Vigor NF.')
	
	parser.add_argument('nf', type=str, help='path to the NF')
	parser.add_argument('--locks', help='use locking mechanisms')

	args = parser.parse_args()

	call_paths = symbex(args.nf)
	analyze_call_paths(args.nf, call_paths)
	shared_nothing = rss_conf_from_lvas()
	
	synthesize_nf(args.nf, call_paths, shared_nothing)
	stitch_synthesized_nf()