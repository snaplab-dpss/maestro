NF_FILES := bridge_main.c bridge_config.c dyn_value.h.gen.c loop.c state.c stat_key.h.gen.c

NF_ARGS := --expire $(or $(EXPIRATION_TIME),100000000) --capacity $(or $(CAPACITY),65536)

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
