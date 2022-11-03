# get current dir, see https://stackoverflow.com/a/8080530
SELF_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# DPDK stuff
include $(RTE_SDK)/mk/rte.vars.mk

# Same name for everyone, makes it easier to run them all with the same script
APP := nf
# allow the use of advanced globs in paths
SHELL := /bin/bash -O extglob -O globstar -c
# NF base source;
# somehow because of DPDK makefile magic wildcards mess up everything here,
# so we ask echo to expand those
SRCS-y = ./nf.c
# Compiler flags
CFLAGS += -std=gnu11
CFLAGS += -DCAPACITY_POW2
CFLAGS += -O3
CFLAGS += -mrtm
# CFLAGS += -O0 -g -rdynamic -DENABLE_LOG -Wfatal-errors

# GCC optimizes a checksum check in rte_ip.h into a CMOV, which is a very poor choice
# that causes 99th percentile latency to go through the roof;
# force it to not do that with no-if-conversion
ifeq ($(CC),gcc)
CFLAGS += -fno-if-conversion -fno-if-conversion2
endif

include $(RTE_SDK)/mk/rte.extapp.mk