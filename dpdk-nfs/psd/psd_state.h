#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include "psd_loop.h"

struct State {
  struct Map *srcs;
  struct Vector *srcs_key;
  struct Vector *touched_ports_counter;
  struct DoubleChain *allocator;

  struct Map *ports;
  struct Vector *ports_key;

  uint32_t capacity;
  uint32_t max_ports;
  uint32_t dev_count;
};

struct State *alloc_state(uint32_t capacity, uint64_t max_ports,
                          uint32_t dev_count);
#endif  //_STATE_H_INCLUDED_
