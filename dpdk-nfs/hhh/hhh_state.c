#include "hhh_state.h"

#include <stdlib.h>

#include "lib/verified/boilerplate-util.h"
#ifdef KLEE_VERIFICATION
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/ether.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/verified/lpm-dir-24-8-control.h"

bool dyn_val_condition(void *value, int index, void *state) {
  struct DynamicValue *v = value;
  return (0 <= v->bucket_time) AND(v->bucket_time <= recent_time())
      AND(v->bucket_size <= 3750000000);
}

#endif  // KLEE_VERIFICATION

struct State *allocated_nf_state = NULL;

uint32_t calculate_n_subnets(uint32_t subnets_mask) {
  uint32_t n = 0;
  for (uint8_t b = 0; b < 32; b++) {
    if (subnets_mask & 1) {
      n++;
    }

    subnets_mask = subnets_mask >> 1;
  }

  return n;
}

struct State *alloc_state(uint64_t link_capacity, uint8_t threshold,
                          uint32_t subnets_mask, uint32_t capacity,
                          uint32_t dev_count) {
  if (allocated_nf_state != NULL) return allocated_nf_state;

  struct State *ret = malloc(sizeof(struct State));

  if (ret == NULL) return NULL;

  uint8_t n_subnets = calculate_n_subnets(subnets_mask);
  ret->n_subnets = n_subnets;

  uint64_t threshold_rate = (link_capacity / 8) * (threshold * 0.01);
  ret->threshold_rate = threshold_rate;

  ret->subnet_indexers =
      (struct Map **)malloc(sizeof(struct Map *) * n_subnets);
  ret->allocators =
      (struct DoubleChain **)malloc(sizeof(struct DoubleChain *) * n_subnets);
  ret->subnet_buckets =
      (struct Vector **)malloc(sizeof(struct Vector *) * n_subnets);
  ret->subnets = (struct Vector **)malloc(sizeof(struct Vector *) * n_subnets);

  for (uint8_t i = 0; i < n_subnets; i++) {
    ret->subnet_indexers[i] = NULL;
    if (map_allocate(ip_addr_eq, ip_addr_hash, capacity,
                     &(ret->subnet_indexers[i])) == 0) {
      return NULL;
    }

    ret->allocators[i] = NULL;
    if (dchain_allocate(capacity, &(ret->allocators[i])) == 0) {
      return NULL;
    }

    ret->subnet_buckets[i] = NULL;
    if (vector_allocate(sizeof(struct DynamicValue), capacity,
                        DynamicValue_allocate,
                        &(ret->subnet_buckets[i])) == 0) {
      return NULL;
    }

    ret->subnets[i] = NULL;
    if (vector_allocate(sizeof(struct ip_addr), capacity, ip_addr_allocate,
                        &(ret->subnets[i])) == 0) {
      return NULL;
    }

#ifdef KLEE_VERIFICATION
    map_set_layout(ret->subnet_indexers[i], ip_addr_descrs,
                   sizeof(ip_addr_descrs) / sizeof(ip_addr_descrs[0]),
                   ip_addr_nests,
                   sizeof(ip_addr_nests) / sizeof(ip_addr_nests[0]), "ip_addr");
    vector_set_layout(
        ret->subnet_buckets[i], DynamicValue_descrs,
        sizeof(DynamicValue_descrs) / sizeof(DynamicValue_descrs[0]),
        DynamicValue_nests,
        sizeof(DynamicValue_nests) / sizeof(DynamicValue_nests[0]),
        "DynamicValue");
    vector_set_entry_condition(ret->subnet_buckets[i], dyn_val_condition, ret);
    vector_set_layout(
        ret->subnets[i], ip_addr_descrs,
        sizeof(ip_addr_descrs) / sizeof(ip_addr_descrs[0]), ip_addr_nests,
        sizeof(ip_addr_nests) / sizeof(ip_addr_nests[0]), "ip_addr");
#endif  // KLEE_VERIFICATION
  }

  ret->capacity = capacity;
  ret->dev_count = dev_count;

  allocated_nf_state = ret;
  return ret;
}

#ifdef KLEE_VERIFICATION
void nf_loop_iteration_border(unsigned lcore_id, vigor_time_t time) {
  loop_iteration_border(
      &allocated_nf_state->subnet_indexers, &allocated_nf_state->allocators,
      &allocated_nf_state->subnet_buckets, &allocated_nf_state->subnets,
      allocated_nf_state->n_subnets, allocated_nf_state->capacity,
      allocated_nf_state->dev_count, lcore_id, time);
}

#endif  // KLEE_VERIFICATION
