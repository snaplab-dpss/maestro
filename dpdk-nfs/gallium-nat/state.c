#include "state.h"

#include <stdlib.h>

#include "lib/verified/boilerplate-util.h"

#ifdef KLEE_VERIFICATION
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#endif // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(int max_flows, uint32_t ext_ip) {
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

  ret->port_counter = NULL;
  if (vector_allocate(sizeof(struct Counter), 1, counter_allocate,
                      &(ret->port_counter)) == 0) {
    return NULL;
  }

  ret->max_flows = max_flows;
  ret->ext_ip = ext_ip;

#ifdef KLEE_VERIFICATION
  map_set_layout(ret->table, flow_descrs,
                 sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                 sizeof(flow_nests) / sizeof(flow_nests[0]), "Flow");
  vector_set_layout(ret->flows, flow_descrs,
                    sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                    sizeof(flow_nests) / sizeof(flow_nests[0]), "Flow");
  vector_set_layout(
      ret->port_counter, counter_descrs,
      sizeof(counter_descrs) / sizeof(counter_descrs[0]), counter_nests,
      sizeof(counter_nests) / sizeof(counter_nests[0]), "Counter");
  vector_set_entry_condition(ret->port_counter, counter_invariant, ret);
#endif // KLEE_VERIFICATION

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(&allocated_nf_state->table, &allocated_nf_state->flows,
                        &allocated_nf_state->port_counter,
                        allocated_nf_state->max_flows,
                        allocated_nf_state->ext_ip, lcore_id, time);
}

#endif // KLEE_VERIFICATION
