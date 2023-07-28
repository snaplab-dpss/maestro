#include "state.h"
#include <stdlib.h>
#include "lib/verified/boilerplate-util.h"
#ifdef KLEE_VERIFICATION
#include "lib/models/verified/ether.h"
#endif  // KLEE_VERIFICATION
struct State* allocated_nf_state = NULL;

struct State* alloc_state() {
  return NULL;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(lcore_id, time);
}

#endif  // KLEE_VERIFICATION
