#!/usr/bin/python3

import sys
import pathlib

MAESTRO_DIR=pathlib.Path(__file__).parent.absolute()
BOILERPLATE=f"{MAESTRO_DIR}/boilerplate.c"
SYNTHESIZED=f"{MAESTRO_DIR}/build/maestro/nf.process.gen.c"
PARALLEL_NF=f"{MAESTRO_DIR}/build/maestro/nf.c"

INIT_TAG="@init"
PROCESS_TAG="@process"

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

stitch_synthesized_nf()