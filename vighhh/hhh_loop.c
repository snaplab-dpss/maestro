#include <klee/klee.h>

#include "hhh_loop.h"

#include "libvig/models/verified/vigor-time-control.h"
#include "libvig/models/verified/double-chain-control.h"
#include "libvig/models/verified/map-control.h"
#include "libvig/models/verified/vector-control.h"

void loop_reset(struct Map ***prefix_indexers, struct DoubleChain ***allocators,
                struct Vector ***prefix_buckets, struct Vector ***prefixes,
                int n_prefixes, uint32_t capacity, uint32_t dev_count,
                unsigned int lcore_id, vigor_time_t *time) {
  for (int i = 0; i < n_prefixes; i++) {
    map_reset((*prefix_indexers)[i]);
    dchain_reset((*allocators)[i], capacity);
    vector_reset((*prefix_buckets)[i]);
    vector_reset((*prefixes)[i]);
  }

  *time = restart_time();
}

void loop_invariant_consume(struct Map ***prefix_indexers,
                            struct DoubleChain ***allocators,
                            struct Vector ***prefix_buckets,
                            struct Vector ***prefixes, int n_prefixes,
                            uint32_t capacity, uint32_t dev_count,
                            unsigned int lcore_id, vigor_time_t time) {
  klee_trace_ret();

  for (int i = 0; i < n_prefixes; i++) {
    klee_trace_param_ptr((*prefix_indexers)[i], sizeof(struct Map *),
                         "prefix_indexers");
    klee_trace_param_ptr((*allocators)[i], sizeof(struct DoubleChain *),
                         "allocators");
    klee_trace_param_ptr((*prefix_buckets)[i], sizeof(struct Vector *),
                         "prefix_buckets");
    klee_trace_param_ptr((*prefixes)[i], sizeof(struct Vector *), "prefixes");
  }

  klee_trace_param_u32(n_prefixes, "n_prefixes");
  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map ***prefix_indexers,
                            struct DoubleChain ***allocators,
                            struct Vector ***prefix_buckets,
                            struct Vector ***prefixes, int n_prefixes,
                            uint32_t capacity, uint32_t dev_count,
                            unsigned int *lcore_id, vigor_time_t *time) {
  klee_trace_ret();

  for (int i = 0; i < n_prefixes; i++) {
    klee_trace_param_ptr((*prefix_indexers)[i], sizeof(struct Map *),
                         "prefix_indexers");
    klee_trace_param_ptr((*allocators)[i], sizeof(struct DoubleChain *),
                         "allocators");
    klee_trace_param_ptr((*prefix_buckets)[i], sizeof(struct Vector *),
                         "prefix_buckets");
    klee_trace_param_ptr((*prefixes)[i], sizeof(struct Vector *), "prefixes");
  }

  klee_trace_param_u32(n_prefixes, "n_prefixes");
  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map ***prefix_indexers,
                           struct DoubleChain ***allocators,
                           struct Vector ***prefix_buckets,
                           struct Vector ***prefixes, int n_prefixes,
                           uint32_t capacity, uint32_t dev_count,
                           unsigned int lcore_id, vigor_time_t time) {
  loop_invariant_consume(prefix_indexers, allocators, prefix_buckets, prefixes,
                         n_prefixes, capacity, dev_count, lcore_id, time);
  loop_reset(prefix_indexers, allocators, prefix_buckets, prefixes, n_prefixes,
             capacity, dev_count, lcore_id, &time);
  loop_invariant_produce(prefix_indexers, allocators, prefix_buckets, prefixes,
                         n_prefixes, capacity, dev_count, &lcore_id, &time);
}
