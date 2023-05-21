#ifndef _STATE_H_INCLUDED_
#define _STATE_H_INCLUDED_

#include "loop.h"
#include "flow.h"
#include "counter.h"

struct State {
  struct Map *table;
  struct Vector *flows;
  struct Vector *port_counter;
  int max_flows;
  uint32_t ext_ip;
};

struct State *alloc_state(int max_flows, uint32_t ext_ip);

#endif //_STATE_H_INCLUDED_
