#!/usr/bin/python3

import sys
import pathlib
import os
import glob
import re
import argparse

# env vars
KLEE_DIR=os.getenv("KLEE_DIR")

if not KLEE_DIR:
	print("Missing KLEE_DIR env var. Exiting.")
	exit(1)

MAESTRO_DIR=pathlib.Path(__file__).parent.absolute()

BOILERPLATE = f"{MAESTRO_DIR}/boilerplate.c"
SYNTHESIZED = f"{MAESTRO_DIR}/build/maestro/nf.process.gen.c"
SYNTHESIZED_XML = f"{MAESTRO_DIR}/build/maestro/nf.process.gen.xml"
PARALLEL_NF = f"{MAESTRO_DIR}/build/maestro/nf.c"

def synthesize_nf(nf):
	if not os.path.isdir(f"{nf}/klee-last"):
		print("No call paths. Run \"make symbex\" first.")
		exit(1)

	CALL_PATHS = glob.glob(f"{nf}/klee-last/*.call_path")
	CALL_PATHS.sort(key=lambda f: int(re.sub('\D', '', f)))

	LIBVIG_CALL_PATHS_TO_C_CODE = f"{KLEE_DIR}/build/bin/libvig-call-paths-to-C-code"
	LIBVIG_CALL_PATHS_TO_C_CODE_ARGS = f"-out={SYNTHESIZED} -xml={SYNTHESIZED_XML} {' '.join(CALL_PATHS)}"

	os.system(f"{LIBVIG_CALL_PATHS_TO_C_CODE} {LIBVIG_CALL_PATHS_TO_C_CODE_ARGS}")

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

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Synthesize a parallel implementation of a Vigor NF.')
	
	parser.add_argument('nf', type=str, help='path to the NF')
	parser.add_argument('--locks', help='use locking mechanisms')

	args = parser.parse_args()

	synthesize_nf(args.nf)
	stitch_synthesized_nf()