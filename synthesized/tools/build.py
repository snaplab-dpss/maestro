#!/usr/bin/python3

import pathlib
import glob
import argparse
import os
import subprocess
import re

SYNTHESIZED_DIR = pathlib.Path(__file__).parent.parent.absolute()

BOILERPLATE_DIR		= f"{SYNTHESIZED_DIR}/boilerplate"
SYNTHESIZED_BUILD	= f"{SYNTHESIZED_DIR}/build"
MAKEFILES_DIR		= f"{SYNTHESIZED_DIR}/makefiles"
SYNTHESIZED_CODE 	= f"{SYNTHESIZED_BUILD}/synthesized"
SYNTHESIZED_APP		= f"{SYNTHESIZED_DIR}/build/app"

subprocess.call([ "mkdir", "-p", SYNTHESIZED_CODE ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.call([ "mkdir", "-p", SYNTHESIZED_APP ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

BOILERPLATE_CHOICE_BMV2				= "bmv2_ss_grpc_controller"
BOILERPLATE_CHOICE_CALL_PATH_HITTER = "call_path_hitter"
BOILERPLATE_CHOICE_LOCKS 			= "locks"
BOILERPLATE_CHOICE_SQ 				= "sequential"
BOILERPLATE_CHOICE_SN 				= "shared-nothing"
BOILERPLATE_CHOICE_TM 				= "tm"

BOILERPLATE_TO_MAKEFILE = {
  BOILERPLATE_CHOICE_BMV2: 				f"{MAKEFILES_DIR}/Makefile.bmv2_controller",
  BOILERPLATE_CHOICE_CALL_PATH_HITTER:	f"{MAKEFILES_DIR}/Makefile.cph",
  BOILERPLATE_CHOICE_LOCKS:				f"{MAKEFILES_DIR}/Makefile.maestro",
  BOILERPLATE_CHOICE_SQ:				f"{MAKEFILES_DIR}/Makefile.maestro",
  BOILERPLATE_CHOICE_SN:				f"{MAKEFILES_DIR}/Makefile.maestro",
  BOILERPLATE_CHOICE_TM:				f"{MAKEFILES_DIR}/Makefile.maestro",
}

BOILERPLATE_CHOICES = [
	BOILERPLATE_CHOICE_BMV2,
	BOILERPLATE_CHOICE_CALL_PATH_HITTER,
	BOILERPLATE_CHOICE_LOCKS,
	BOILERPLATE_CHOICE_SQ,
	BOILERPLATE_CHOICE_SN,
	BOILERPLATE_CHOICE_TM,
]

def build_impl(boilerplate, impl, extras=[]):
	complete_impl = ""
	
	with open(f"{BOILERPLATE_DIR}/{boilerplate}.c", 'r') as f:
		complete_impl += f.read()

	complete_impl += "\n"

	for extra in extras:
		complete_impl += extra
		complete_impl += "\n"

	with open(impl, 'r') as f:
		complete_impl += f.read()

	complete_impl += "\n"
	
	with open(f"{SYNTHESIZED_CODE}/nf.c", 'w') as f:
		f.write(complete_impl)

def get_original_nf_srcs(nf):
	original_nf_files = []

	# get pre processed source code
	original_nf_files += glob.glob(f"{nf}/build/app/*.i")

	if not original_nf_files:
		subprocess.call([ "make", "pre-processor" ], cwd=nf)
		original_nf_files += glob.glob(f"{nf}/build/app/*.i")
		assert original_nf_files

	return original_nf_files

def find_function_def(nf, impl, fname):
	signature = ''

	# get function signature first
	with open(impl, 'r') as f:
		generated_src = f.read()
		found = re.findall(f"([^\\s]+\\s{fname}.+)\\s*;", generated_src)
		assert found
		signature = found[0].rstrip()
		# print(f'Signature found: "{signature}"')

	src_files = get_original_nf_srcs(nf)

	for src_file in src_files:
		with open(src_file, 'r') as f:
			src = f.read()

			# remove all pre-processing comments
			line_comments = re.compile('#.*$', re.MULTILINE)
			src = line_comments.sub('', src)

			found = re.search(f'({fname}.+)\\s*{{', src)

			if not found:
				continue
		
			pos = found.start()
			assert pos >= 0
			
			function_def = f'{signature} {{'
			finished = False
			scope = 0

			# find start of definition after signature
			while pos < len(src):
				c = src[pos]
				pos += 1

				if c == '{':
					scope += 1
					break
			
			assert scope == 1

			# go until the end
			while pos < len(src):
				c = src[pos]
				pos += 1
				function_def += c

				if c == '}':
					scope -= 1

					if scope == 0:
						finished = True
						break
				elif c == '{':
					scope += 1

			assert scope == 0
			assert finished

			print(f'Definition found: {signature} in {src_file}')
			# print(function_def)
			return function_def
		
	print(f'Definition of {fname} not found.')
	exit(1)

def find_type_def(nf, impl, tname):
	src_files = get_original_nf_srcs(nf)

	for src_file in src_files:
		with open(src_file, 'r') as f:
			src = f.read()

			# remove all pre-processing comments
			line_comments = re.compile('#.*$', re.MULTILINE)
			src = line_comments.sub('', src)

			found = re.search(f'({tname}.+)\\s*{{', src)

			if not found:
				continue
		
			pos = found.start()
			assert pos >= 0
			
			type_def = f'{tname} {{'
			finished = False
			scope = 0

			# find start of definition after signature
			while pos < len(src):
				c = src[pos]
				pos += 1

				if c == '{':
					scope += 1
					break
			
			assert scope == 1

			# go until the end
			while pos < len(src):
				c = src[pos]
				pos += 1
				type_def += c

				if c == '}':
					scope -= 1

					if scope == 0:
						finished = True
						break
				elif c == '{':
					scope += 1

			assert scope == 0
			assert finished

			print(f'Definition found: {tname} in {src_file}')
			# print(function_def)
			return type_def + ';'
		
	print(f'Definition of {tname} not found.')
	exit(1)

def get_missing_function_defs(make_output):
	return list(set(re.findall("undefined reference to `(.+)'", make_output)))

def get_missing_type_defs(make_output):
	return list(set(re.findall("incomplete type ‘(.+)’", make_output)))

def compile(makefile):
	subprocess.call([ "cp", makefile, f"{SYNTHESIZED_CODE}/Makefile" ])

	stdout = subprocess.PIPE
	stderr = subprocess.PIPE

	proc = subprocess.Popen([ "make" ], cwd=SYNTHESIZED_CODE, stdout=stdout, stderr=stderr)
	proc.wait()

	stderr = proc.stderr.read().decode()
	return proc.returncode == 0, stderr

def final_compilation(makefile):
	subprocess.call([ "cp", makefile, f"{SYNTHESIZED_CODE}/Makefile" ])
	subprocess.call([ "make" ], cwd=SYNTHESIZED_CODE)
	subprocess.call([ "cp", f"{SYNTHESIZED_CODE}/build/app/nf", f"{SYNTHESIZED_APP}/nf" ])

# I know, I know... this is absolutely horrible. But a deadline approaches...
def get_user_defined_functions(nf, impl, missing_defs):
	user_def_func = []

	for m in missing_defs:
		definition = find_function_def(nf, impl, m)
		user_def_func.append(definition)
		
	return user_def_func

def get_user_defined_types(nf, impl, missing_defs):
	user_def_types = []

	for m in missing_defs:
		definition = find_type_def(nf, impl, m)
		user_def_types.append(definition)
		
	return user_def_types

def find_missing_code(nf, impl, makefile_report):
	missing_defs = get_missing_function_defs(makefile_report)

	if missing_defs:
		print('Missing function: ', missing_defs)
		return get_user_defined_functions(nf, impl, missing_defs)
	
	missing_defs = get_missing_type_defs(makefile_report)

	if missing_defs:
		print('Missing types: ', missing_defs)
		return get_user_defined_types(nf, impl, missing_defs)
	
	print(makefile_report)
	exit(1)

def build(boilerplate, impl, nf):
	assert boilerplate in BOILERPLATE_TO_MAKEFILE
	makefile = BOILERPLATE_TO_MAKEFILE[boilerplate]

	build_impl(boilerplate, impl)
	success, makefile_report = compile(makefile)

	extras = []
	while not success:
		last_report = makefile_report

		extra_code = find_missing_code(nf, impl, makefile_report)
		extras = extra_code + extras
		build_impl(boilerplate, impl, extras)
		success, makefile_report = compile(makefile)

		if makefile_report == last_report:
			print(makefile_report)
			print('Getting the same report after trying to fix it.')
			exit(1)
	
	final_compilation(makefile)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Bundle synthesized NF with existing Vigor NF.')
  
	parser.add_argument('impl', type=str, help='path to the file containing nf_init and nf_process implementations')
	parser.add_argument('boilerplate', help='name of the boilerplate file', choices=BOILERPLATE_CHOICES)
	parser.add_argument('nf', type=str, help='path to the original NF')

	args = parser.parse_args()
	args.nf = os.path.abspath(args.nf)

	build(args.boilerplate, args.impl, args.nf)

	print('Done!')
	print(f'Synthesized file: {SYNTHESIZED_CODE}/nf.c')
	print(f'Binary file: {SYNTHESIZED_APP}/nf')
