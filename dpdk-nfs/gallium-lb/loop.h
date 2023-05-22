#pragma once

#include "lib/verified/double-chain.h"
#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/vigor-time.h"

void loop_invariant_consume(struct Map **table, struct Vector **flows,
                            struct DoubleChain **allocator,
                            struct Vector **flows_backends,
                            struct Vector **backends, uint32_t max_flows,
                            unsigned int lcore_id, vigor_time_t time);

void loop_invariant_produce(struct Map **table, struct Vector **flows,
                            struct DoubleChain **allocator,
                            struct Vector **flows_backends,
                            struct Vector **backends, uint32_t max_flows,
                            unsigned int *lcore_id, vigor_time_t *time);

void loop_iteration_border(struct Map **table, struct Vector **flows,
                           struct DoubleChain **allocator,
                           struct Vector **flows_backends,
                           struct Vector **backends, uint32_t max_flows,
                           unsigned int lcore_id, vigor_time_t time);