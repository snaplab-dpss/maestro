#!/usr/bin/python3

import pathlib
import glob
import argparse
import os
import subprocess

SYNTHESIZED_DIR = pathlib.Path(__file__).parent.absolute()
SYNTHESIZED_BUILD = f"{SYNTHESIZED_DIR}/build"
SYNTHESIZED_BUNDLE = f"{SYNTHESIZED_BUILD}/bundle"

subprocess.call([ "mkdir", "-p", SYNTHESIZED_BUNDLE ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_original_nf_srcs(nf):
  original_nf_files = []

  if not nf:
    return original_nf_files

  original_nf_files += glob.glob(f"{nf}/*.c")
  original_nf_files += glob.glob(f"{nf}/*.h")
  original_nf_files += glob.glob(f"{nf}/*.py")
  original_nf_files += glob.glob(f"{nf}/*.ml")

  for f in original_nf_files:
    subprocess.call([ "cp", f, SYNTHESIZED_BUNDLE ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

  return original_nf_files

def build_makefile(extra_vars_makefile, nf, srcs):
  MAKEFILE = ""
  for f in srcs:
    if len(MAKEFILE) == 0:
      MAKEFILE += f"ORIGINAL_NF_FILES_ABS_PATH := {os.path.abspath(f)}\n"
      MAKEFILE += f"ORIGINAL_NF_FILES_BASE := {os.path.basename(f)}\n\n"
    else:
      MAKEFILE += f"ORIGINAL_NF_FILES_ABS_PATH += {os.path.abspath(f)}\n"
      MAKEFILE += f"ORIGINAL_NF_FILES_BASE += {os.path.basename(f)}\n\n"
  
  MAKEFILE += f"SYNTHESIZED_FILE := {SYNTHESIZED_DIR}/build/synthesized/nf.c\n"
  MAKEFILE += f"\ninclude {os.path.abspath(extra_vars_makefile)}\n"

  if not nf:
    MAKEFILE += f"include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile\n"
  else:
    MAKEFILE += f"include {nf}/Makefile\n"

  makefile = open(f"{SYNTHESIZED_BUNDLE}/Makefile.nf", mode='w')
  makefile.write(MAKEFILE)
  makefile.close()

def build():
  subprocess.call([ "make", "-f", "Makefile.nf" ], cwd=SYNTHESIZED_BUNDLE)
  subprocess.call([ "cp", f"{SYNTHESIZED_BUNDLE}/build/app/*", f"{SYNTHESIZED_BUILD}/app" ],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description='Bundle synthesized NF with existing Vigor NF.')
  
  parser.add_argument('extra_vars_makefile', type=str, help='path to the Makefile containing the extra vars')
  parser.add_argument('--nf', type=str, help='path to the original NF')

  args = parser.parse_args()

  if args.nf:
    args.nf = os.path.abspath(args.nf)

  srcs = get_original_nf_srcs(args.nf)
  build_makefile(args.extra_vars_makefile, args.nf, srcs)
  build()
