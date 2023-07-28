#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include "cl_loop.h"

struct State {
  struct Map *flows;
  struct Vector *flows_keys;
  struct DoubleChain *flow_allocator;

  struct Sketch *sketch;

  uint32_t max_flows;
  uint32_t dev_count;
};

struct State *alloc_state(uint32_t max_flows, uint32_t sketch_capacity,
                          uint16_t max_clients, uint32_t dev_count);
#endif  //_STATE_H_INCLUDED_
