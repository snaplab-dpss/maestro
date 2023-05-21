#pragma once

#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/vigor-time.h"

void loop_invariant_consume(struct Map **table, struct Vector **flows,
                            struct Vector **flows_counter,
                            struct Vector **backends,
                            struct Vector **backends_counter,
                            unsigned int lcore_id, vigor_time_t time);

void loop_invariant_produce(struct Map **table, struct Vector **flows,
                            struct Vector **flows_counter,
                            struct Vector **backends,
                            struct Vector **backends_counter,
                            unsigned int *lcore_id, vigor_time_t *time);

void loop_iteration_border(struct Map **table, struct Vector **flows,
                           struct Vector **flows_counter,
                           struct Vector **backends,
                           struct Vector **backends_counter,
                           unsigned int lcore_id, vigor_time_t time);