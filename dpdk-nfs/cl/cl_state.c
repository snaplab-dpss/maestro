#include "cl_state.h"

#include <stdlib.h>
#include <assert.h>

#include "lib/verified/boilerplate-util.h"
#ifdef KLEE_VERIFICATION
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/ether.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/unverified/sketch-control.h"
#include "lib/models/verified/lpm-dir-24-8-control.h"
#endif  // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(uint32_t max_flows, uint32_t sketch_capacity,
                          uint16_t max_clients, uint32_t dev_count) {
  if (allocated_nf_state != NULL) return allocated_nf_state;

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL) return NULL;

  ret->max_flows = max_flows;
  ret->dev_count = dev_count;

  ret->flows = NULL;
  if (map_allocate(flow_eq, flow_hash, max_flows, &(ret->flows)) == 0) {
    return NULL;
  }

  ret->flows_keys = NULL;
  if (vector_allocate(sizeof(struct flow), max_flows, flow_allocate,
                      &(ret->flows_keys)) == 0) {
    return NULL;
  }

  ret->flow_allocator = NULL;
  if (dchain_allocate(max_flows, &(ret->flow_allocator)) == 0) {
    return NULL;
  }

  ret->sketch = NULL;
  if (sketch_allocate(client_hash, sketch_capacity, max_clients,
                      &(ret->sketch)) == 0) {
    return NULL;
  }

#ifdef KLEE_VERIFICATION
  map_set_layout(ret->flows, flow_descrs,
                 sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                 sizeof(flow_nests) / sizeof(flow_nests[0]), "flow");
  vector_set_layout(ret->flows_keys, flow_descrs,
                    sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                    sizeof(flow_nests) / sizeof(flow_nests[0]), "flow");
  sketch_set_layout(ret->sketch, client_descrs,
                    sizeof(client_descrs) / sizeof(client_descrs[0]),
                    client_nests,
                    sizeof(client_nests) / sizeof(client_nests[0]), "client");
#endif  // KLEE_VERIFICATION

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(
      &allocated_nf_state->flows, &allocated_nf_state->flows_keys,
      &allocated_nf_state->flow_allocator, &allocated_nf_state->sketch,
      allocated_nf_state->max_flows, allocated_nf_state->dev_count, lcore_id,
      time);
}

#endif  // KLEE_VERIFICATION
