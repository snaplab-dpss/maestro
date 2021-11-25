#include "psd_state.h"

#include <stdlib.h>

#include "libvig/verified/boilerplate-util.h"
#ifdef KLEE_VERIFICATION
#include "libvig/models/verified/double-chain-control.h"
#include "libvig/models/verified/ether.h"
#include "libvig/models/verified/map-control.h"
#include "libvig/models/verified/vector-control.h"
#include "libvig/models/verified/lpm-dir-24-8-control.h"

#endif // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(uint32_t capacity, uint64_t max_ports,
                          uint32_t dev_count) {
  if (allocated_nf_state != NULL)
    return allocated_nf_state;

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL)
    return NULL;

  ret->capacity = capacity;

  ret->srcs = NULL;
  if (map_allocate(ip_addr_eq, ip_addr_hash, capacity, &(ret->srcs)) == 0) {
    return NULL;
  }

  ret->srcs_key = NULL;
  if (vector_allocate(sizeof(struct ip_addr), capacity, ip_addr_allocate,
                      &(ret->srcs_key)) == 0) {
    return NULL;
  }

  ret->allocator = NULL;
  if (dchain_allocate(capacity, &(ret->allocator)) == 0) {
    return NULL;
  }

  ret->scanned_ports = NULL;
  if (vector_allocate(sizeof(struct ScannedPorts), capacity,
                      ScannedPorts_allocate, &(ret->scanned_ports)) == 0) {
    return NULL;
  }

#ifdef KLEE_VERIFICATION
  map_set_layout(ret->srcs, ip_addr_descrs,
                 sizeof(ip_addr_descrs) / sizeof(ip_addr_descrs[0]),
                 ip_addr_nests,
                 sizeof(ip_addr_nests) / sizeof(ip_addr_nests[0]), "ip_addr");
  vector_set_layout(
      ret->srcs_key, ip_addr_descrs,
      sizeof(ip_addr_descrs) / sizeof(ip_addr_descrs[0]), ip_addr_nests,
      sizeof(ip_addr_nests) / sizeof(ip_addr_nests[0]), "ip_addr");
  vector_set_layout(ret->scanned_ports, ScannedPorts_descrs,
                    sizeof(ScannedPorts_descrs) /
                        sizeof(ScannedPorts_descrs[0]),
                    ScannedPorts_nests,
                    sizeof(ScannedPorts_nests) / sizeof(ScannedPorts_nests[0]),
                    "ScannedPorts");
#endif // KLEE_VERIFICATION

  ret->capacity = capacity;
  ret->dev_count = dev_count;

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(
      &allocated_nf_state->srcs, &allocated_nf_state->srcs_key,
      &allocated_nf_state->allocator, &allocated_nf_state->scanned_ports,
      allocated_nf_state->capacity, allocated_nf_state->dev_count, lcore_id,
      time);
}

#endif // KLEE_VERIFICATION
