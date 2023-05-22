#include "state.h"

#include "lib/verified/boilerplate-util.h"

#include <stdlib.h>

#ifdef KLEE_VERIFICATION
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#endif // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(uint32_t max_flows, uint32_t expiration_time,
                          uint32_t num_backends) {
  if (allocated_nf_state != NULL) {
    return allocated_nf_state;
  }

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL) {
    return NULL;
  }

  ret->table = NULL;
  if (map_allocate(flow_eq, flow_hash, max_flows, &(ret->table)) == 0) {
    return NULL;
  }

  ret->flows = NULL;
  if (vector_allocate(sizeof(struct Flow), max_flows, flow_allocate,
                      &(ret->flows)) == 0) {
    return NULL;
  }

  ret->allocator = NULL;
  if (dchain_allocate(max_flows, &(ret->allocator)) == 0) {
    return NULL;
  }

  ret->flows_backends = NULL;
  if (vector_allocate(sizeof(struct Backend), max_flows, backend_allocate,
                      &(ret->flows_backends)) == 0) {
    return NULL;
  }

  ret->backends = NULL;
  if (vector_allocate(sizeof(struct Backend), num_backends, backend_allocate,
                      &(ret->backends)) == 0) {
    return NULL;
  }

#ifdef KLEE_VERIFICATION
  map_set_layout(ret->table, flow_descrs,
                 sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                 sizeof(flow_nests) / sizeof(flow_nests[0]), "flow");
  vector_set_layout(ret->flows, flow_descrs,
                    sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                    sizeof(flow_nests) / sizeof(flow_nests[0]), "flow");
  vector_set_layout(
      ret->flows_backends, backend_descrs,
      sizeof(backend_descrs) / sizeof(backend_descrs[0]), backend_nests,
      sizeof(backend_nests) / sizeof(backend_nests[0]), "flows_backends");
  vector_set_layout(
      ret->backends, backend_descrs,
      sizeof(backend_descrs) / sizeof(backend_descrs[0]), backend_nests,
      sizeof(backend_nests) / sizeof(backend_nests[0]), "backend");
#endif // KLEE_VERIFICATION

  ret->max_flows = max_flows;
  ret->expiration_time = expiration_time;
  ret->num_backends = num_backends;

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(&allocated_nf_state->table, &allocated_nf_state->flows,
                        &allocated_nf_state->allocator,
                        &allocated_nf_state->flows_backends,
                        &allocated_nf_state->backends,
                        allocated_nf_state->max_flows, lcore_id, time);
}

#endif // KLEE_VERIFICATION
