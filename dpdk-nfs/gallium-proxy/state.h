#pragma once

#include "loop.h"

#include "backend.h"
#include "entry.h"

struct State {
  struct Map *table;
  struct Vector *entries;
  struct Vector *values;
};

struct State *alloc_state(uint32_t capacity);