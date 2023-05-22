#include "lb_manager.h"

#include "lib/unverified/util.h"
#include "lib/verified/expirator.h"

#include <assert.h>
#include <string.h>

bool allocate_flow(struct State *state, struct Flow *flow,
                   uint32_t *new_dst_addr, vigor_time_t now) {
  int index;
  if (dchain_allocate_new_index(state->allocator, &index, now) == 0) {
    return false;
  }

  unsigned hash = hash_obj((void *)flow, sizeof(struct Flow));
  int backend_index = hash % state->num_backends;

  struct Flow *key = 0;
  struct Backend *chosen = 0;
  struct Backend *backend = 0;

  vector_borrow(state->flows, index, (void **)&key);
  vector_borrow(state->flows_backends, index, (void **)&chosen);
  vector_borrow(state->backends, backend_index, (void **)&backend);

  memcpy((void *)key, (void *)flow, sizeof(struct Flow));
  memcpy((void *)chosen, (void *)backend, sizeof(struct Backend));
  map_put(state->table, key, index);
  *new_dst_addr = backend->ip;

  vector_return(state->flows, index, key);
  vector_return(state->flows_backends, index, chosen);
  vector_return(state->backends, backend_index, backend);

  return true;
}

void expire_flows(struct State *state, vigor_time_t now) {
  assert(now >= 0); // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)now; // OK because of the two asserts
  vigor_time_t vigor_time_expiration = (vigor_time_t)state->expiration_time;
  vigor_time_t last_time = time_u - vigor_time_expiration * 1000; // us to ns
  expire_items_single_map(state->allocator, state->flows, state->table,
                          last_time);
}

bool match_backend_and_expire_flow(struct State *state, struct Flow *flow,
                                   uint32_t *new_dst_addr) {
  int index;
  int present = map_get(state->table, flow, &index);

  if (!present) {
    return false;
  }

  struct Backend *chosen;
  vector_borrow(state->flows_backends, index, (void **)&chosen);
  *new_dst_addr = chosen->ip;
  vector_return(state->flows_backends, index, chosen);

  dchain_free_index(state->allocator, index);

  void *key = 0;
  vector_borrow(state->flows, index, &key);
  map_erase(state->table, key, &key);
  vector_return(state->flows, index, key);

  return true;
}

bool match_backend(struct State *state, struct Flow *flow,
                   uint32_t *new_dst_addr, vigor_time_t now) {
  int index;
  int present = map_get(state->table, flow, &index);

  if (!present) {
    return false;
  }

  dchain_rejuvenate_index(state->allocator, index, now);

  struct Backend *chosen;
  vector_borrow(state->flows_backends, index, (void **)&chosen);
  *new_dst_addr = chosen->ip;
  vector_return(state->flows_backends, index, chosen);

  return true;
}