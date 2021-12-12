#ifndef _CL_LOOP_H_INCLUDED_
#define _CL_LOOP_H_INCLUDED_

#include "libvig/verified/double-chain.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/cht.h"
#include "libvig/verified/lpm-dir-24-8.h"
#include "libvig/proof/coherence.h"
#include "libvig/verified/vigor-time.h"
#include "libvig/unverified/sketch.h"

#include "flow.h"
#include "client.h"

void loop_invariant_consume(struct Map **flows, struct Vector **flows_keys,
                            struct DoubleChain **flow_allocator,
                            struct Sketch **sketch, uint32_t max_flows,
                            uint32_t dev_count, unsigned int lcore_id,
                            vigor_time_t time);

void loop_invariant_produce(struct Map **flows, struct Vector **flows_keys,
                            struct DoubleChain **flow_allocator,
                            struct Sketch **sketch, uint32_t max_flows,
                            uint32_t dev_count, unsigned int *lcore_id,
                            vigor_time_t *time);

void loop_iteration_border(struct Map **flows, struct Vector **flows_keys,
                           struct DoubleChain **flow_allocator,
                           struct Sketch **sketch, uint32_t max_flows,
                           uint32_t dev_count, unsigned int lcore_id,
                           vigor_time_t time);

#endif //_PSD_LOOP_H_INCLUDED_
