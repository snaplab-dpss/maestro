#include "state.h"

#include <stdlib.h>

#include "lib/verified/boilerplate-util.h"

#ifdef KLEE_VERIFICATION
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/ether.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/verified/lpm-dir-24-8-control.h"
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
