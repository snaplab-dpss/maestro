#include <klee/klee.h>
#include "lib/unverified/expirator.h"
#include "../verified/double-chain-control.h"

int expire_items_single_map_iteratively(struct Vector *vector, struct Map *map,
                                        int start, int n_elems) {
  klee_trace_ret();
  klee_trace_param_u64((uint64_t)vector, "vector");
  klee_trace_param_u64((uint64_t)map, "map");
  klee_trace_param_i32(start, "start");
  klee_trace_param_i32(n_elems, "n_elems");
  int nfreed = klee_int("number_of_freed_flows");
  klee_assume(0 <= nfreed);
  return nfreed;
}
