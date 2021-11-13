#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include "hhh_loop.h"

struct State {
  struct Map **prefix_indexers;
  struct DoubleChain **allocators;
  struct Vector **prefix_buckets;
  struct Vector **prefixes;
  uint64_t threshold_rate; // B/s
  int n_prefixes;
  uint32_t capacity;
  uint32_t dev_count;
};

struct State *alloc_state(uint64_t link_capacity, uint8_t threshold,
                          uint8_t min_prefix, uint8_t max_prefix,
                          uint32_t capacity, uint32_t dev_count);
#endif //_STATE_H_INCLUDED_
