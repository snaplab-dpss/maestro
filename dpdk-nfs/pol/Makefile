NF_FILES := policer_main.c policer_config.c dynamic_value.c ip_addr.c state.c

NF_ARGS := --wan 0 \
           --lan 1 \
           --rate $(or $(POLICER_RATE),1000000000) \
           --burst $(or $(POLICER_BURST),10000000000) \
           --capacity $(or $(CAPACITY),65536)

NF_LAYER := 3

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
