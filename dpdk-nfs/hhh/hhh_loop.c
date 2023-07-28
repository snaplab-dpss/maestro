#ifdef KLEE_VERIFICATION
#include <klee/klee.h>

#include "hhh_loop.h"

#include "lib/models/verified/vigor-time-control.h"
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"

void loop_reset(struct Map ***subnet_indexers, struct DoubleChain ***allocators,
                struct Vector ***subnet_buckets, struct Vector ***subnets,
                int n_subnets, uint32_t capacity, uint32_t dev_count,
                unsigned int lcore_id, vigor_time_t *time) {
  for (int i = 0; i < n_subnets; i++) {
    map_reset((*subnet_indexers)[i]);
    dchain_reset((*allocators)[i], capacity);
    vector_reset((*subnet_buckets)[i]);
    vector_reset((*subnets)[i]);
  }

  *time = restart_time();
}

void loop_invariant_consume(struct Map ***subnet_indexers,
                            struct DoubleChain ***allocators,
                            struct Vector ***subnet_buckets,
                            struct Vector ***subnets, int n_subnets,
                            uint32_t capacity, uint32_t dev_count,
                            unsigned int lcore_id, vigor_time_t time) {
  klee_trace_ret();

  for (int i = 0; i < n_subnets; i++) {
    klee_trace_param_ptr(&(*subnet_indexers)[i], sizeof(struct Map *),
                         "subnet_indexers");
    klee_trace_param_ptr(&(*allocators)[i], sizeof(struct DoubleChain *),
                         "allocators");
    klee_trace_param_ptr(&(*subnet_buckets)[i], sizeof(struct Vector *),
                         "subnet_buckets");
    klee_trace_param_ptr(&(*subnets)[i], sizeof(struct Vector *), "subnets");
  }

  klee_trace_param_u32(n_subnets, "n_subnets");
  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map ***subnet_indexers,
                            struct DoubleChain ***allocators,
                            struct Vector ***subnet_buckets,
                            struct Vector ***subnets, int n_subnets,
                            uint32_t capacity, uint32_t dev_count,
                            unsigned int *lcore_id, vigor_time_t *time) {
  klee_trace_ret();

  for (int i = 0; i < n_subnets; i++) {
    klee_trace_param_ptr(&(*subnet_indexers)[i], sizeof(struct Map *),
                         "subnet_indexers");
    klee_trace_param_ptr(&(*allocators)[i], sizeof(struct DoubleChain *),
                         "allocators");
    klee_trace_param_ptr(&(*subnet_buckets)[i], sizeof(struct Vector *),
                         "subnet_buckets");
    klee_trace_param_ptr(&(*subnets)[i], sizeof(struct Vector *), "subnets");
  }

  klee_trace_param_u32(n_subnets, "n_subnets");
  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map ***subnet_indexers,
                           struct DoubleChain ***allocators,
                           struct Vector ***subnet_buckets,
                           struct Vector ***subnets, int n_subnets,
                           uint32_t capacity, uint32_t dev_count,
                           unsigned int lcore_id, vigor_time_t time) {
  loop_invariant_consume(subnet_indexers, allocators, subnet_buckets, subnets,
                         n_subnets, capacity, dev_count, lcore_id, time);
  loop_reset(subnet_indexers, allocators, subnet_buckets, subnets, n_subnets,
             capacity, dev_count, lcore_id, &time);
  loop_invariant_produce(subnet_indexers, allocators, subnet_buckets, subnets,
                         n_subnets, capacity, dev_count, &lcore_id, &time);
}
#endif  // KLEE_VERIFICATION