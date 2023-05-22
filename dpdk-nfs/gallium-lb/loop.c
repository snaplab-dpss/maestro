#ifdef KLEE_VERIFICATION

#include "loop.h"

#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/verified/vigor-time-control.h"

#include <klee/klee.h>

void loop_reset(struct Map **table, struct Vector **flows,
                struct DoubleChain **allocator, struct Vector **flows_backends,
                struct Vector **backends, uint32_t max_flows,
                unsigned int lcore_id, vigor_time_t *time) {
  map_reset(*table);
  vector_reset(*flows);
  dchain_reset(*allocator, max_flows);
  vector_reset(*flows_backends);
  vector_reset(*backends);
  *time = restart_time();
}

void loop_invariant_consume(struct Map **table, struct Vector **flows,
                            struct DoubleChain **allocator,
                            struct Vector **flows_backends,
                            struct Vector **backends, uint32_t max_flows,
                            unsigned int lcore_id, vigor_time_t time) {
  klee_trace_ret();
  klee_trace_param_ptr(table, sizeof(struct Map *), "table");
  klee_trace_param_ptr(flows, sizeof(struct Vector *), "flows");
  klee_trace_param_ptr(allocator, sizeof(struct DoubleChain *), "allocator");
  klee_trace_param_ptr(flows_backends, sizeof(struct Vector *),
                       "flows_backends");
  klee_trace_param_ptr(backends, sizeof(struct Vector *), "backends");
  klee_trace_param_i32(max_flows, "max_flows");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map **table, struct Vector **flows,
                            struct DoubleChain **allocator,
                            struct Vector **flows_backends,
                            struct Vector **backends, uint32_t max_flows,
                            unsigned int *lcore_id, vigor_time_t *time) {
  klee_trace_ret();
  klee_trace_param_ptr(table, sizeof(struct Map *), "table");
  klee_trace_param_ptr(flows, sizeof(struct Vector *), "flows");
  klee_trace_param_ptr(allocator, sizeof(struct DoubleChain *), "allocator");
  klee_trace_param_ptr(flows_backends, sizeof(struct Vector *),
                       "flows_backends");
  klee_trace_param_ptr(backends, sizeof(struct Vector *), "backends");
  klee_trace_param_i32(max_flows, "max_flows");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map **table, struct Vector **flows,
                           struct DoubleChain **allocator,
                           struct Vector **flows_backends,
                           struct Vector **backends, uint32_t max_flows,
                           unsigned int lcore_id, vigor_time_t time) {
  loop_invariant_consume(table, flows, allocator, flows_backends, backends,
                         max_flows, lcore_id, time);
  loop_reset(table, flows, allocator, flows_backends, backends, max_flows,
             lcore_id, &time);
  loop_invariant_produce(table, flows, allocator, flows_backends, backends,
                         max_flows, &lcore_id, &time);
}

#endif // KLEE_VERIFICATION