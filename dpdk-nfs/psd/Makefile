NF_FILES := psd_main.c psd_config.c psd_state.c ip_addr.c counter.c touched_port.c psd_loop.c

NF_ARGS := --wan 0 \
           --lan 1 \
           --capacity $(or $(CAPACITY),65536) \
           --max-ports $(or $(MAX_PORTS),64) \
           --expire $(or $(EXPIRATION_TIME),10000000)

NF_LAYER := 4

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
