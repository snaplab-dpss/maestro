NF_FILES := nat_main.c nat_config.c nat_flowmanager.c flow.c counter.c loop.c state.c

NF_ARGS := --wan 1 \
           --lan 0 \
           --max-flows 65536 \
           --extip $(or $(EXTERNAL_IP),0.0.0.0)

NF_LAYER := 4


include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
