NF_FILES := cl_main.c cl_config.c cl_state.c flow.c client.c

NF_ARGS := --lan 1 \
           --wan 0 \
           --max-flows $(or $(CAPACITY),65536) \
           --capacity $(or $(CAPACITY),1024) \
           --max-clients $(or $(MAX_PORTS),64) \
           --expire-flow $(or $(EXPIRATION_TIME),100000000) \
           --expire-client $(or $(EXPIRATION_TIME),100000000) \

NF_LAYER := 4

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
