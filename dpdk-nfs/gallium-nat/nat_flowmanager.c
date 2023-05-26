#include "nat_flowmanager.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <rte_byteorder.h>

#include "lib/verified/map.h"
#include "lib/verified/vector.h"

#include "state.h"

bool allocate_flow(struct State *state, struct Flow *flow,
                   uint16_t *external_port) {
  struct Counter *counter = 0;
  vector_borrow(state->port_counter, 0, (void **)&counter);

  if (counter->value >= state->max_flows) {
    vector_return(state->port_counter, 0, counter);
    return false;
  }

  int current_counter = counter->value;
  counter->value++;
  vector_return(state->port_counter, 0, counter);

  struct Flow *key = 0;
  vector_borrow(state->flows, current_counter, (void **)&key);
  memcpy((void *)key, (void *)flow, sizeof(struct Flow));
  map_put(state->table, key, current_counter);
  vector_return(state->flows, current_counter, key);

  *external_port = rte_be_to_cpu_16(current_counter);

  return true;
}

bool internal_get(struct State *state, struct Flow *flow,
                  uint16_t *external_port) {
  int index;
  if (map_get(state->table, flow, &index) == 0) {
    return false;
  }

  *external_port = index;
  return true;
}

bool external_get(struct State *state, uint16_t external_port,
                  struct Flow *out_flow) {
  struct Flow *key = 0;
  vector_borrow(state->flows, external_port, (void **)&key);
  memcpy((void *)out_flow, (void *)key, sizeof(struct Flow));
  vector_return(state->flows, external_port, key);

  return true;
}
