#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include "hhh_loop.h"

struct State {
  struct Map **subnet_indexers;
  struct DoubleChain **allocators;
  struct Vector **subnet_buckets;
  struct Vector **subnets;
  uint64_t threshold_rate;  // B/s
  int n_subnets;
  uint32_t capacity;
  uint32_t dev_count;
};

struct State *alloc_state(uint64_t link_capacity, uint8_t threshold,
                          uint32_t subnets_mask, uint32_t capacity,
                          uint32_t dev_count);
#endif  //_STATE_H_INCLUDED_
