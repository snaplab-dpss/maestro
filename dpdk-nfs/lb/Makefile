# Need 3 devices otherwise the concept of a load-balancer doesn't make sense
NF_DEVICES := 3

NF_FILES := lb_main.c lb_balancer.c lb_config.c ip_addr.c lb_backend.c lb_flow.c loop.c state.c

NF_AUTOGEN_SRCS := lb_flow.h lb_backend.h ip_addr.h

# CHT height must be a prime number
NF_ARGS := --flow-expiration $(or $(EXPIRATION_TIME),100000000) \
           --flow-capacity $(or $(CAPACITY),65536) \
           --backend-capacity 32 \
           --cht-height 97 \
           --backend-expiration 100000000 \
           --wan $(or $(WAN_DEVICE), 2)

NF_LAYER := 3

NF_BENCH_NEEDS_REVERSE_TRAFFIC := true

include $(abspath $(dir $(lastword $(MAKEFILE_LIST))))/../Makefile
