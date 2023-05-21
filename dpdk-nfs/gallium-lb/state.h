#pragma once

#include "loop.h"

#include "backend.h"
#include "flow.h"
#include "counter.h"

struct State {
  struct Map *table;
  struct Vector *flows;
  struct Vector *flows_counter;
  struct Vector *backends;
  struct Vector *backends_counter;
  uint32_t capacity;
  uint32_t max_backends;
};

struct State *alloc_state(uint32_t capacity, uint32_t max_backends);