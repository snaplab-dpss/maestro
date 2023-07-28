#ifndef _LOOP_H_INCLUDED_
#define _LOOP_H_INCLUDED_

#include "lib/verified/double-chain.h"
#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/cht.h"
#include "lib/verified/lpm-dir-24-8.h"
#include "lib/proof/coherence.h"
#include "lib/verified/vigor-time.h"

#include "stat_key.h"
#include "dyn_value.h"

void loop_invariant_consume(struct Map** dyn_map, struct Vector** dyn_keys,
                            struct Vector** dyn_vals, struct Map** st_map,
                            struct Vector** st_vec,
                            struct DoubleChain** dyn_heap, uint32_t capacity,
                            uint32_t stat_capacity, uint32_t dev_count,
                            unsigned int lcore_id, vigor_time_t time);

void loop_invariant_produce(struct Map** dyn_map, struct Vector** dyn_keys,
                            struct Vector** dyn_vals, struct Map** st_map,
                            struct Vector** st_vec,
                            struct DoubleChain** dyn_heap, uint32_t capacity,
                            uint32_t stat_capacity, uint32_t dev_count,
                            unsigned int* lcore_id, vigor_time_t* time);

void loop_iteration_border(struct Map** dyn_map, struct Vector** dyn_keys,
                           struct Vector** dyn_vals, struct Map** st_map,
                           struct Vector** st_vec,
                           struct DoubleChain** dyn_heap, uint32_t capacity,
                           uint32_t stat_capacity, uint32_t dev_count,
                           unsigned int lcore_id, vigor_time_t time);

#endif  //_LOOP_H_INCLUDED_
