#pragma once

#include "lib/verified/vigor-time.h"
#include "state.h"
#include <stdint.h>

bool allocate_flow(struct State *state, struct Flow *flow,
                   uint32_t *new_dst_addr, vigor_time_t now);
void expire_flows(struct State *state, vigor_time_t now);
bool match_backend_and_expire_flow(struct State *state, struct Flow *flow,
                                   uint32_t *new_dst_addr);
bool match_backend(struct State *state, struct Flow *flow,
                   uint32_t *new_dst_addr, vigor_time_t now);