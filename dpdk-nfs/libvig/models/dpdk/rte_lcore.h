#pragma once

#include "klee/klee.h"

#define MAX_NUM_LCORES 64

static inline unsigned rte_socket_id(void) { return 0; }

static inline unsigned rte_lcore_id(void) { return 0; }

static inline unsigned rte_lcore_count(void) {
  klee_trace_ret();
  unsigned lcores = klee_range(1, MAX_NUM_LCORES, "lcores");
  return lcores;
}
