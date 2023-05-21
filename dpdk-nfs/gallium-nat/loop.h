#ifndef _LOOP_H_INCLUDED_
#define _LOOP_H_INCLUDED_

#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/vigor-time.h"

void loop_invariant_consume(struct Map **table, struct Vector **flows,
                            struct Vector **port_counter, int max_flows,
                            uint32_t ext_ip, unsigned int lcore_id,
                            vigor_time_t time);

void loop_invariant_produce(struct Map **table, struct Vector **flows,
                            struct Vector **port_counter, int max_flows,
                            uint32_t ext_ip, unsigned int *lcore_id,
                            vigor_time_t *time);

void loop_iteration_border(struct Map **table, struct Vector **flows,
                           struct Vector **port_counter, int max_flows,
                           uint32_t ext_ip, unsigned int lcore_id,
                           vigor_time_t time);

#endif //_LOOP_H_INCLUDED_
