#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include "loop.h"

#include "backend.h"
#include "entry.h"

struct State {
  struct Map *table;
  struct Vector *entries;
  struct Vector *values;
};

struct State *alloc_state(uint32_t capacity);

#endif //_STATE_H_INCLUDED_
