#ifndef _PSD_LOOP_H_INCLUDED_
#define _PSD_LOOP_H_INCLUDED_

#include "libvig/verified/double-chain.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/cht.h"
#include "libvig/verified/lpm-dir-24-8.h"
#include "libvig/proof/coherence.h"
#include "libvig/verified/vigor-time.h"

#include "ip_addr.h"
#include "counter.h"
#include "touched_port.h"

void loop_invariant_consume(struct Map **srcs, struct Vector **srcs_keys,
                            struct Vector **touched_ports_counter,
                            struct DoubleChain **allocator, struct Map **ports,
                            struct Vector **ports_key, uint32_t capacity,
                            uint32_t max_ports, uint32_t dev_count,
                            unsigned int lcore_id, vigor_time_t time);

void loop_invariant_produce(struct Map **srcs, struct Vector **srcs_keys,
                            struct Vector **touched_ports_counter,
                            struct DoubleChain **allocator, struct Map **ports,
                            struct Vector **ports_key, uint32_t capacity,
                            uint32_t max_ports, uint32_t dev_count,
                            unsigned int *lcore_id, vigor_time_t *time);

void loop_iteration_border(struct Map **srcs, struct Vector **srcs_keys,
                           struct Vector **touched_ports_counter,
                           struct DoubleChain **allocator, struct Map **ports,
                           struct Vector **ports_key, uint32_t capacity,
                           uint32_t max_ports, uint32_t dev_count,
                           unsigned int lcore_id, vigor_time_t time);

#endif //_PSD_LOOP_H_INCLUDED_
