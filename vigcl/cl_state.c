#include "cl_state.h"

#include <stdlib.h>

#include "libvig/verified/boilerplate-util.h"
#ifdef KLEE_VERIFICATION
#include "libvig/models/verified/double-chain-control.h"
#include "libvig/models/verified/ether.h"
#include "libvig/models/verified/map-control.h"
#include "libvig/models/verified/vector-control.h"
#include "libvig/models/verified/lpm-dir-24-8-control.h"

#endif // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

struct State *alloc_state(uint32_t max_flows, uint32_t sketch_capacity,
                          uint16_t max_clients, uint32_t dev_count) {
  if (allocated_nf_state != NULL)
    return allocated_nf_state;

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL)
    return NULL;

  ret->max_flows = max_flows;
  ret->sketch_capacity = sketch_capacity;
  ret->max_clients = max_clients;
  ret->dev_count = dev_count;

  ret->flows = NULL;
  if (map_allocate(flow_eq, flow_hash, max_flows, &(ret->flows)) == 0) {
    return NULL;
  }

  ret->flows_keys = NULL;
  if (vector_allocate(sizeof(struct flow), max_flows, flow_allocate,
                      &(ret->flows_keys)) == 0) {
    return NULL;
  }

  ret->flow_allocator = NULL;
  if (dchain_allocate(max_flows, &(ret->flow_allocator)) == 0) {
    return NULL;
  }

  ret->clients = NULL;
  if (map_allocate(hash_eq, hash_hash, sketch_capacity * SKETCH_HASHES,
                   &(ret->clients)) == 0) {
    return NULL;
  }

  ret->clients_keys = NULL;
  if (vector_allocate(sizeof(struct hash), sketch_capacity * SKETCH_HASHES,
                      hash_allocate, &(ret->clients_keys)) == 0) {
    return NULL;
  }

  ret->clients_buckets = NULL;
  if (vector_allocate(sizeof(struct bucket), sketch_capacity * SKETCH_HASHES,
                      bucket_allocate, &(ret->clients_buckets)) == 0) {
    return NULL;
  }

  for (int i = 0; i < SKETCH_HASHES; i++) {
    ret->client_allocator[i] = NULL;
    if (dchain_allocate(sketch_capacity, &(ret->client_allocator[i])) == 0) {
      return NULL;
    }
  }

#ifdef KLEE_VERIFICATION
  map_set_layout(ret->flows, flow_descrs,
                 sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                 sizeof(flow_nests) / sizeof(flow_nests[0]), "flow");
  vector_set_layout(ret->flows_keys, flow_descrs,
                    sizeof(flow_descrs) / sizeof(flow_descrs[0]), flow_nests,
                    sizeof(flow_nests) / sizeof(flow_nests[0]), "flow");
  map_set_layout(ret->clients, hash_descrs,
                 sizeof(hash_descrs) / sizeof(hash_descrs[0]), hash_nests,
                 sizeof(hash_nests) / sizeof(hash_nests[0]), "hash");
  vector_set_layout(ret->clients_keys, hash_descrs,
                    sizeof(hash_descrs) / sizeof(hash_descrs[0]), hash_nests,
                    sizeof(hash_nests) / sizeof(hash_nests[0]), "hash");
  vector_set_layout(ret->clients_buckets, bucket_descrs,
                    sizeof(bucket_descrs) / sizeof(bucket_descrs[0]),
                    bucket_nests,
                    sizeof(bucket_nests) / sizeof(bucket_nests[0]), "bucket");
#endif // KLEE_VERIFICATION

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(
      &allocated_nf_state->flows, &allocated_nf_state->flows_keys,
      &allocated_nf_state->flow_allocator, &allocated_nf_state->clients,
      &allocated_nf_state->clients_keys, &allocated_nf_state->clients_buckets,
      allocated_nf_state->client_allocator, allocated_nf_state->max_flows,
      allocated_nf_state->sketch_capacity, allocated_nf_state->dev_count,
      lcore_id, time);
}

#endif // KLEE_VERIFICATION
