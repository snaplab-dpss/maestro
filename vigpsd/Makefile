NF_FILES := psd_main.c psd_config.c psd_state.c ip_addr.c scanned_ports.c

NF_ARGS := --lan 0 \
           --wan 1 \
           --capacity $(or $(CAPACITY),65536) \
           --max-ports $(or $(MAX_PORTS),60) \
           --expire $(or $(EXPIRATION_TIME),1000000)

NF_LAYER := 4

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
