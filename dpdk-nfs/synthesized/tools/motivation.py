#!/usr/bin/python3

import pathlib
import glob
import argparse
import os
import subprocess

SYNTHESIZED_DIR = pathlib.Path(__file__).parent.parent.absolute()

EXTRA_VARS_MAKEFILE = f"{SYNTHESIZED_DIR}/Makefile.maestro"

BOILERPLATE_DIR = f"{SYNTHESIZED_DIR}/boilerplate"
MOTIVATION_DIR = f"{BOILERPLATE_DIR}/motivation"
SYNTHESIZED_BUILD = f"{SYNTHESIZED_DIR}/build"

SYNTHESIZED_APP = f"{SYNTHESIZED_BUILD}/app"
SYNTHESIZED_CODE = f"{SYNTHESIZED_BUILD}/synthesized"
SYNTHESIZED_BUNDLE = f"{SYNTHESIZED_BUILD}/bundle"

subprocess.call([ "rm", "-rf", SYNTHESIZED_APP ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.call([ "rm", "-rf", SYNTHESIZED_BUNDLE ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

subprocess.call([ "mkdir", "-p", SYNTHESIZED_APP ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.call([ "mkdir", "-p", SYNTHESIZED_CODE ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.call([ "mkdir", "-p", SYNTHESIZED_BUNDLE ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

CHOICE_ATOMIC = "atomic"
CHOICE_LOCKS = "locks"
CHOICE_SN = "shared-nothing"
CHOICE_TM = "tm"
CHOICE_UNPROTECTED = "unprotected"

def copy_src(approach):
  subprocess.call([ "cp", f"{MOTIVATION_DIR}/{approach}.c", f"{SYNTHESIZED_CODE}/nf.c" ])

def build_makefile():
  MAKEFILE = "" 
  MAKEFILE += f"SYNTHESIZED_FILE := {SYNTHESIZED_DIR}/build/synthesized/nf.c\n"
  MAKEFILE += f"\ninclude {os.path.abspath(EXTRA_VARS_MAKEFILE)}\n"

  MAKEFILE += f"include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile\n"

  makefile = open(f"{SYNTHESIZED_BUNDLE}/Makefile.nf", mode='w')
  makefile.write(MAKEFILE)
  makefile.close()

def build(approach):
  copy_src(approach)
  build_makefile()

  subprocess.call([ "make", "-f", "Makefile.nf" ], cwd=SYNTHESIZED_BUNDLE)
  subprocess.call([ "cp" ] +  glob.glob(f"{SYNTHESIZED_BUNDLE}/build/app/*") + [ f"{SYNTHESIZED_APP}/" ])
  
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Build motivational NF.')
  
  parser.add_argument('approach',																			\
    help='name of the parallelization approach', 											\
    choices=[
      CHOICE_ATOMIC,
      CHOICE_LOCKS,
      CHOICE_SN,
      CHOICE_TM,
      CHOICE_UNPROTECTED,
    ])

  args = parser.parse_args()

  build(args.approach)
