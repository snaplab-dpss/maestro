#include "state.h"

#include "lib/verified/boilerplate-util.h"

#include <stdlib.h>

#ifdef KLEE_VERIFICATION
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#endif // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(uint32_t capacity, uint32_t max_backends) {
  if (allocated_nf_state != NULL) {
    return allocated_nf_state;
  }

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL) {
    return NULL;
  }

  ret->table = NULL;
  if (map_allocate(flow_eq, flow_hash, capacity, &(ret->table)) == 0) {
    return NULL;
  }

  ret->flows = NULL;
  if (vector_allocate(sizeof(struct Flow), capacity, flow_allocate,
                      &(ret->flows)) == 0) {
    return NULL;
  }

  ret->flows_counter = NULL;
  if (vector_allocate(sizeof(struct Counter), 1, counter_allocate,
                      &(ret->flows_counter)) == 0) {
    return NULL;
  }

  ret->backends = NULL;
  if (vector_allocate(sizeof(struct Backend), max_backends, backend_allocate,
                      &(ret->backends)) == 0) {
    return NULL;
  }

  ret->backends_counter = NULL;
  if (vector_allocate(sizeof(struct Counter), 1, counter_allocate,
                      &(ret->backends_counter)) == 0) {
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
      ret->flows_counter, counter_descrs,
      sizeof(counter_descrs) / sizeof(counter_descrs[0]), counter_nests,
      sizeof(counter_nests) / sizeof(counter_nests[0]), "counter");
  vector_set_entry_condition(ret->flows_counter, flows_counter_invariant, ret);
  vector_set_layout(
      ret->backends, backend_descrs,
      sizeof(backend_descrs) / sizeof(backend_descrs[0]), backend_nests,
      sizeof(backend_nests) / sizeof(backend_nests[0]), "backend");
  vector_set_layout(
      ret->backends_counter, counter_descrs,
      sizeof(counter_descrs) / sizeof(counter_descrs[0]), counter_nests,
      sizeof(counter_nests) / sizeof(counter_nests[0]), "counter");
  vector_set_entry_condition(ret->backends_counter, backends_counter_invariant,
                             ret);
#endif // KLEE_VERIFICATION

  ret->capacity = capacity;
  ret->max_backends = max_backends;

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(&allocated_nf_state->table, &allocated_nf_state->flows,
                        &allocated_nf_state->flows_counter,
                        &allocated_nf_state->backends,
                        &allocated_nf_state->backends_counter, lcore_id, time);
}

#endif // KLEE_VERIFICATION
