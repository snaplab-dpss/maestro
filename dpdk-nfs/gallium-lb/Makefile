NF_FILES := lb_main.c lb_config.c loop.c state.c flow.c backend.c lb_manager.c cfg_parser.c

NF_ARGS := --lan 0 \
           --wan 1 \
           --capacity $(or $(CAPACITY),65536) \
           --backends $(or $(BACKENDS),64)

NF_LAYER := 4

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
