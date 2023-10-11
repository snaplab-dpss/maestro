# Maestro

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/snaplab-dpss/maestro/main/assets/logo-white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/snaplab-dpss/maestro/main/assets/logo-black.svg">
  <img align="right" width="200" alt="Maestro" src="./assets/logo-black.svg">
</picture>

This repository contains the source code for the Maestro project, a system that automatically parallelizes software network functions written in the DPDK framework.

Maestro tries to employ a shared-nothing parallel architecture, wherein packets accessing the same state are always sent to the same core, thus completely avoiding the requirement for locking mechanisms. This is achieved by carefully configuring the RSS mechanism to forward packets accessing the same state to the same core.

In order to to this, and with help of the [Vigor](git@github.com:vigor-nf/vigor.git) framework, Maestro first runs exhaustive symbolic execution (ESE) on the NF to extract its functionality. Using the information extracted from the ESE, it builds a model of how the NF maintains its state. It then uses this information to infer if a shared-nothing parallel solution can be employed, wherein packets accessing the same state are always sent to the same core, thus completely avoiding locking mechanisms. It extracts constraints that packets that must be sent to the same core must satisfy, and feeds those contraints into the [Z3](https://github.com/Z3Prover/z3) SMT solver. This is responsible for finding the RSS configuration that satisfies those constraints, enabling shared-nothing parallelization.

Maestro can also be configured to parallelize with locking mechanisms, and with hardware transactional memory ([RTM](https://www.intel.com/content/www/us/en/docs/cpp-compiler/developer-guide-reference/2021-8/restricted-transactional-memory-overview.html)).

## Tested OSs

- Ubuntu 20.04
- Ubuntu 22.04
- Ubuntu 23.04

## Setup

### Synchronizing every submodule

Almost all of Maestro's dependencies live inside the [deps](https://github.com/snaplab-dpss/maestro/tree/nsdi24/deps) folder as submodules. As such, the first step after cloning this repo should be to recursively update the submodules:

```bash
$ git submodule update --init --recursive
```

### Building

This will install each Maestro dependency, and Maestro itself, locally on a folder named `deps`. It requires an active Internet connection to download the dependencies.

⚠️ **WARNING**: this might take a long time to finish, depending on your machine. It will also consume a lot of system resources, mainly CPU and RAM.

```bash
$ build.sh
```

## Running on a container

To build the container:

1. Synchronize every submodule (see instructions above)
2. Build the container with `docker-compose build` (warning: this will take a long time)
3. Connect with the built container with `docker-compose run maestro`

## Running Maestro

### Start the Maestro environment.

This will export the required environment variables, and setup a python virtual environment.

📣 **Contrary to the previous steps, run this step every time you want to run Maestro.**

```bash
$ source paths.sh
```

### Running the Maestro pipeline

To run the complete Maestro pipeline, use the `maestro/maestro.py` script.

Run `maestro/maestro.py -h` to show the help menu:

```
$ maestro/maestro.py -h
usage: maestro.py [-h] [--target {seq,sn,locks,tm}] [--symbex] --out OUT [--var VAR] nf

Parallelize a Vigor NF.

positional arguments:
  nf                    path to the NF

options:
  -h, --help            show this help message and exit
  --target {seq,sn,locks,tm}
                        implementation model target
  --symbex              Rerun symbolic execution
  --out OUT             Output file
  --var VAR             NF configuration variable for symbex (e.g., --var EXPIRATION_TIME=123). Requires --symbex flag to take effect.
```

Here is an example of how to run Maestro to parallelize the NOP NF under a shared-nothing model:

```bash
$ maestro/maestro.py dpdk-nfs/nop --target sn --out synthesized/nop-sn.c
KLEE: Using Z3 solver backend
KLEE: Using Z3 solver backend
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000001.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000002.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000003.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000004.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000005.call_path
No devices. Using default unique devices value (2).

Packet field dependencies:

Devices:
  0
  1
No constraints. Configuring RSS with every possible option available.

RS3 configuration:
cores: 8
keys : 2
cfgs :
	opt: Geneve OAM
	sz : 40 bits
	pfs:
		* VXLAN UDP outer
		* VXLAN VNI
	opt: VXLAN GPE OAM
	sz : 40 bits
	pfs:
		* VXLAN UDP outer
		* VXLAN VNI
	opt: Non-frag TCP/IPv4
	sz : 96 bits
	pfs:
		* IPv4 src
		* IPv4 dst
		* TCP src
		* TCP dst
	opt: Non-frag UDP/IPv4
	sz : 96 bits
	pfs:
		* IPv4 src
		* IPv4 dst
		* UDP src
		* UDP dst
	opt: Non-frag SCTP/IPv4
	sz : 128 bits
	pfs:
		* IPv4 src
		* IPv4 dst
		* SCTP src
		* SCTP dst
		* SCTP verification
	opt: Non-frag TCP/IPv6
	sz : 288 bits
	pfs:
		* IPv6 src
		* IPv6 dst
		* TCP src
		* TCP dst
	opt: Non-frag UDP/IPv6
	sz : 288 bits
	pfs:
		* IPv6 src
		* IPv6 dst
		* UDP src
		* UDP dst
	opt: Non-frag SCTP/IPv6
	sz : 320 bits
	pfs:
		* IPv6 src
		* IPv6 dst
		* SCTP src
		* SCTP dst
		* SCTP verification
	opt: Non-frag IPv6
	sz : 256 bits
	pfs:
		* IPv6 src
		* IPv6 dst
	opt: Frag IPv6
	sz : 256 bits
	pfs:
		* IPv6 src
		* IPv6 dst
	opt: Ethertype
	sz : 6 bits
	pfs:
		* Ethertype

No constraints. Generating random keys.
Device 0: 
27 5f 14 90 3b 0e 1a 5e 
a4 99 37 ad de 5d 7f 8c 
4f 01 d3 f6 19 17 64 f4 
14 cc 49 fc 24 ae 4e 4b 
0e 62 db 49 70 f5 a7 14 
8f de c2 6d 3b 41 f9 8b 
42 cd 81 5b 

Device 1: 
6b 41 d2 4a 61 41 7b de 
29 4b c6 8c b4 5d 51 ae 
64 be 5f d5 90 7e 81 33 
2d 53 8a 79 3b 19 13 a7 
5a e5 f1 bb 26 6d 9a 4f 
b8 60 dc 6c bd 2d 1a 21 
eb 79 f6 7c 

Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000001.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000002.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000003.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000004.call_path
Loading: ~/maestro/dpdk-nfs/nop/klee-last/test000005.call_path
KLEE: Using Z3 solver backend
===========================================
type:      return init
value:     SUCCESS
===========================================

===========================================
type:      call
function:  current_time
args:      ret:       (ReadLSB w64 (w32 0) next_time__6)
===========================================

===========================================
type:      branch
condition: (Ne (w16 0)
     (ReadLSB w16 (w32 0) VIGOR_DEVICE))
===========================================

===========================================
type:      return process
operation: fwd(0)
===========================================

===========================================
type:      return process
operation: fwd(1)
===========================================

[nop] Analyzing call paths
[nop] Finding RSS configuration
[nop] Synthesizing
[nop] ================ REPORT ================
[nop] Call path analysis  0:00:00.014908
[nop] Solver              0:00:00.007641
[nop] Synthesize          0:00:01.473334
[nop] Total               0:00:01.496285
[nop] ========================================

```

### Running exhaustive symbolic execution (ESE)

Although one can ask the `maestro.py` script to rerun ESE on an NF, sometimes we may want to manually rerun ESE without triggering the whole Maestro pipeline. To do this:

1. Navigate into the NF's directory
2. Run `make symbex` to manually generate all of the NF's call paths.

The NF's configuration parameters under ESE are inside the makefile on its directory. The final ESE results can be found inside the NF's directory, on a folder entitled `klee-out-{i}` (with `{i}` depending on the number of times ESE was previously run).

Here is the example output of ESE run on the [NOP NF](https://github.com/snaplab-dpss/maestro/tree/nsdi24/dpdk-nfs/nop) NF:

```
$ cd dpdk-nfs/nop
$ make symbex
KLEE: output directory is "~/maestro/dpdk-nfs/nop/klee-out-0"
KLEE: Using Z3 solver backend
KLEE: Deterministic memory allocation starting from 0x40000000
KLEE: WARNING: undefined reference to function: kill (UNSAFE)!
KLEE: WARNING ONCE: Alignment of memory from call "malloc" is not modelled. Using alignment of 8.
KLEE: Deterministic memory allocation starting from 0x40000000

KLEE: done: total instructions = 220410
KLEE: done: completed paths = 5
KLEE: done: generated tests = 5
        Command being timed: "klee -no-externals -allocate-determ -allocate-determ-start-address=0x00040000000 -allocate-determ-size=1000 -dump-call-traces -dump-call-trace-prefixes -solver-backend=z3 -exit-on-error -max-memory=750000 -search=dfs -condone-undeclared-havocs --debug-report-symbdex nf.bc --lcores=0 --no-shconf --no-telemetry -- --lan 0 --wan 1"
        User time (seconds): 1.10
        System time (seconds): 0.03
        Percent of CPU this job got: 96%
        Elapsed (wall clock) time (h:mm:ss or m:ss): 0:01.17
        Average shared text size (kbytes): 0
        Average unshared data size (kbytes): 0
        Average stack size (kbytes): 0
        Average total size (kbytes): 0
        Maximum resident set size (kbytes): 39260
        Average resident set size (kbytes): 0
        Major (requiring I/O) page faults: 159
        Minor (reclaiming a frame) page faults: 5813
        Voluntary context switches: 581
        Involuntary context switches: 2
        Swaps: 0
        File system inputs: 54640
        File system outputs: 5384
        Socket messages sent: 0
        Socket messages received: 0
        Signals delivered: 0
        Page size (bytes): 4096
        Exit status: 0
```



## Pre-generated parallel implementations

We also uploaded all the automatically generated parallel implementations for our NFs. All the NFs can be found in the [dpdk-nfs](https://github.com/snaplab-dpss/maestro/tree/nsdi24/dpdk-nfs) folder, and the Maestro parallel implementations under [synthesized](https://github.com/snaplab-dpss/maestro/tree/nsdi24/synthesized).