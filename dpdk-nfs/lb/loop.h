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
#include "lb_backend.h"
#include "lb_flow.h"

void loop_invariant_consume(
    struct Map** flow_to_flow_id, struct Vector** flow_heap,
    struct DoubleChain** flow_chain, struct Vector** flow_id_to_backend_id,
    struct Map** ip_to_backend_id, struct Vector** backend_ips,
    struct Vector** backends, struct DoubleChain** active_backends,
    struct Vector** cht, uint32_t backend_capacity, uint32_t flow_capacity,
    uint32_t cht_height, unsigned int lcore_id, vigor_time_t time);

void loop_invariant_produce(
    struct Map** flow_to_flow_id, struct Vector** flow_heap,
    struct DoubleChain** flow_chain, struct Vector** flow_id_to_backend_id,
    struct Map** ip_to_backend_id, struct Vector** backend_ips,
    struct Vector** backends, struct DoubleChain** active_backends,
    struct Vector** cht, uint32_t backend_capacity, uint32_t flow_capacity,
    uint32_t cht_height, unsigned int* lcore_id, vigor_time_t* time);

void loop_iteration_border(
    struct Map** flow_to_flow_id, struct Vector** flow_heap,
    struct DoubleChain** flow_chain, struct Vector** flow_id_to_backend_id,
    struct Map** ip_to_backend_id, struct Vector** backend_ips,
    struct Vector** backends, struct DoubleChain** active_backends,
    struct Vector** cht, uint32_t backend_capacity, uint32_t flow_capacity,
    uint32_t cht_height, unsigned int lcore_id, vigor_time_t time);

#endif  //_LOOP_H_INCLUDED_
