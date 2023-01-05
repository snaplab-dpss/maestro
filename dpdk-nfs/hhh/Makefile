NF_FILES := hhh_main.c hhh_config.c hhh_state.c hhh_loop.c ip_addr.c dynamic_value.c

NF_ARGS := --wan 0 --lan 1 --link $(or $(HHH_LINK),10000) --threshold $(or $(HHH_THRESHOLD),50) --subnets-mask $(or $(HHH_SUBNETS_MASK),0x808080) --burst $(or $(HHH_BURST),3750000000) --capacity $(or $(HHH_CAPACITY),65536)

NF_LAYER := 3

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
