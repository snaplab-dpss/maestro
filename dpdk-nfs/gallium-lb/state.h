#pragma once

#include "loop.h"

#include "backend.h"
#include "flow.h"

struct State {
  struct Map *table;
  struct Vector *flows;
  struct DoubleChain *allocator;
  struct Vector *flows_backends;
  struct Vector *backends;
  uint32_t max_flows;
  uint32_t expiration_time;
  uint32_t num_backends;
};

struct State *alloc_state(uint32_t max_flows, uint32_t expiration_time,
                          uint32_t num_backends);