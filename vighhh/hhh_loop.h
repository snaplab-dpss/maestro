#ifndef _HHH_LOOP_H_INCLUDED_
#define _HHH_LOOP_H_INCLUDED_

#include "libvig/verified/double-chain.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/cht.h"
#include "libvig/verified/lpm-dir-24-8.h"
#include "libvig/proof/coherence.h"
#include "libvig/verified/vigor-time.h"

#include "ip_addr.h"
#include "dynamic_value.h"

void loop_invariant_consume(struct Map ***subnet_indexers,
                            struct DoubleChain ***allocators,
                            struct Vector ***subnet_buckets,
                            struct Vector ***subnets, int n_subnets,
                            uint32_t capacity, uint32_t dev_count,
                            unsigned int lcore_id, vigor_time_t time);

void loop_invariant_produce(struct Map ***subnet_indexers,
                            struct DoubleChain ***allocators,
                            struct Vector ***subnet_buckets,
                            struct Vector ***subnets, int n_subnets,
                            uint32_t capacity, uint32_t dev_count,
                            unsigned int *lcore_id, vigor_time_t *time);

void loop_iteration_border(struct Map ***subnet_indexers,
                           struct DoubleChain ***allocators,
                           struct Vector ***subnet_buckets,
                           struct Vector ***subnets, int n_subnets,
                           uint32_t capacity, uint32_t dev_count,
                           unsigned int lcore_id, vigor_time_t time);

#endif //_HHH_LOOP_H_INCLUDED_
