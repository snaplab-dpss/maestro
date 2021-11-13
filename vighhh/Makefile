NF_FILES := hhh_main.c hhh_config.c hhh_state.c ip_addr.c dynamic_value.c

NF_ARGS := --wan 0 --lan 1 --link $(or $(HHH_LINK),10000) --threshold $(or $(HHH_THRESHOLD),50) --min-prefix $(or $(HHH_MIN_PREFIX),8) --max-prefix $(or $(HHH_MAX_PREFIX),8) --burst $(or $(HHH_BURST),3750000000) --capacity $(or $(HHH_CAPACITY),65536)

NF_LAYER := 3

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
