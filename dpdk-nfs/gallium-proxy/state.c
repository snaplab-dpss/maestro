#include "state.h"

#include "lib/verified/boilerplate-util.h"

#include <stdlib.h>

#ifdef KLEE_VERIFICATION
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#endif // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(uint32_t capacity) {
  if (allocated_nf_state != NULL) {
    return allocated_nf_state;
  }

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL) {
    return NULL;
  }

  ret->table = NULL;
  if (map_allocate(entry_eq, entry_hash, capacity, &(ret->table)) == 0) {
    return NULL;
  }

  ret->entries = NULL;
  if (vector_allocate(sizeof(struct Entry), capacity, entry_allocate,
                      &(ret->entries)) == 0) {
    return NULL;
  }

  ret->values = NULL;
  if (vector_allocate(sizeof(struct Backend), capacity, backend_allocate,
                      &(ret->values)) == 0) {
    return NULL;
  }

#ifdef KLEE_VERIFICATION
  map_set_layout(ret->table, entry_descrs,
                 sizeof(entry_descrs) / sizeof(entry_descrs[0]), entry_nests,
                 sizeof(entry_nests) / sizeof(entry_nests[0]), "entry");
  vector_set_layout(ret->entries, entry_descrs,
                    sizeof(entry_descrs) / sizeof(entry_descrs[0]), entry_nests,
                    sizeof(entry_nests) / sizeof(entry_nests[0]), "entry");
  vector_set_layout(
      ret->values, backend_descrs,
      sizeof(backend_descrs) / sizeof(backend_descrs[0]), backend_nests,
      sizeof(backend_nests) / sizeof(backend_nests[0]), "backend");
#endif // KLEE_VERIFICATION

  allocated_nf_state = ret;
  return ret;
}



#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(&allocated_nf_state->table,
                        &allocated_nf_state->entries,
                        &allocated_nf_state->values, lcore_id, time);
}

#endif // KLEE_VERIFICATION
