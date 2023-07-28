#ifndef _LOOP_H_INCLUDED_
#define _LOOP_H_INCLUDED_

#include "lib/verified/double-chain.h"
#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/cht.h"
#include "lib/verified/lpm-dir-24-8.h"
#include "lib/proof/coherence.h"
#include "lib/verified/vigor-time.h"

#include "ip_addr.h"
#include "dynamic_value.h"

void loop_invariant_consume(struct Map** dyn_map, struct Vector** dyn_keys,
                            struct DoubleChain** dyn_heap,
                            struct Vector** dyn_vals, uint32_t capacity,
                            uint32_t dev_count, unsigned int lcore_id,
                            vigor_time_t time);

void loop_invariant_produce(struct Map** dyn_map, struct Vector** dyn_keys,
                            struct DoubleChain** dyn_heap,
                            struct Vector** dyn_vals, uint32_t capacity,
                            uint32_t dev_count, unsigned int* lcore_id,
                            vigor_time_t* time);

void loop_iteration_border(struct Map** dyn_map, struct Vector** dyn_keys,
                           struct DoubleChain** dyn_heap,
                           struct Vector** dyn_vals, uint32_t capacity,
                           uint32_t dev_count, unsigned int lcore_id,
                           vigor_time_t time);

#endif  //_LOOP_H_INCLUDED_
