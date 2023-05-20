NF_FILES := fw_main.c fw_config.c loop.c state.c flow.c cfg_parser.c

NF_ARGS := --lan 0 \
           --wan 1 \
           --capacity $(or $(CAPACITY),65536)

NF_LAYER := 4

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
