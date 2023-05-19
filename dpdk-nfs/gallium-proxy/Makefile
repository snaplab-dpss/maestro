NF_FILES := proxy_main.c proxy_config.c loop.c state.c backend.c entry.c table_file_parser.c

NF_ARGS := --lan 0 \
           --wan 1 \
           --capacity $(or $(CAPACITY),65536)

NF_LAYER := 4

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
