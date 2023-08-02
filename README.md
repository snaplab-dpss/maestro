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

## Setup

### Synchronize every submodule

```
$ git submodule update --init --recursive
```

### Run the build script

This will install each Maestro dependency, and Maestro itself.

⚠️ **WARNING**: this might take a long time to finish, depending on your machine. It will also consume a lot of system resources, mainly CPU and RAM.

```
$ build.sh
```

### Start the Maestro environment.

This will export the required environment variables, and setup a python virtual environment.

📣 **Contrary to the previous steps, run this step every time you want to run Maestro.**

## Running Maestro

### Run in a container

To build the container, first synchronize every submodule (see instructions above), then run `docker-compose build`. To connect with the built container, simply run `docker-compose run maestro`.

### Running exhaustive symbolic execution

To run ESE on an NF, first go into the NF's directory. Then, simply run `make symbex` to generate all of the NF's call paths. The NF's configuration parameters under ESE are inside the makefile on its directory.

### Running the Maestro pipeline

To run the complete Maestro pipeline, use the `maestro/maestro.py` script. Run `maestro/maestro.py -h` to show the help menu.

Here is an example of how to run Maestro to parallelize the NOP NF under a shared-nothing model:

```
$ maestro/maestro.py dpdk-nfs/nop --target sn --out synthesized/nop-sn.c
```

## Pre-generated parallel implementations

We also uploaded all the automatically generated parallel implementations for our NFs. All the NFs can be found in the `dpdk-nfs` folder, and the Maestro parallel implementations under `synthesized`.