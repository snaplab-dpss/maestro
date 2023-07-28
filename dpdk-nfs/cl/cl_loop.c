#ifdef KLEE_VERIFICATION
#include <klee/klee.h>

#include "cl_loop.h"

#include "lib/models/verified/vigor-time-control.h"
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/unverified/sketch-control.h"

void loop_reset(struct Map **flows, struct Vector **flows_keys,
                struct DoubleChain **flow_allocator, struct Sketch **sketch,
                uint32_t max_flows, uint32_t dev_count, unsigned int lcore_id,
                vigor_time_t *time) {
  map_reset(*flows);
  vector_reset(*flows_keys);
  dchain_reset(*flow_allocator, max_flows);
  sketch_reset((*sketch));

  *time = restart_time();
}

void loop_invariant_consume(struct Map **flows, struct Vector **flows_keys,
                            struct DoubleChain **flow_allocator,
                            struct Sketch **sketch, uint32_t max_flows,
                            uint32_t dev_count, unsigned int lcore_id,
                            vigor_time_t time) {
  klee_trace_ret();

  klee_trace_param_ptr(flows, sizeof(struct Map *), "flows");
  klee_trace_param_ptr(flows_keys, sizeof(struct Vector *), "flows_keys");
  klee_trace_param_ptr(flow_allocator, sizeof(struct DoubleChain *),
                       "flow_allocator");
  klee_trace_param_ptr(sketch, sizeof(struct Sketch *), "sketch");

  klee_trace_param_u32(max_flows, "max_flows");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map **flows, struct Vector **flows_keys,
                            struct DoubleChain **flow_allocator,
                            struct Sketch **sketch, uint32_t max_flows,
                            uint32_t dev_count, unsigned int *lcore_id,
                            vigor_time_t *time) {
  klee_trace_ret();

  klee_trace_param_ptr(flows, sizeof(struct Map *), "flows");
  klee_trace_param_ptr(flows_keys, sizeof(struct Vector *), "flows_keys");
  klee_trace_param_ptr(flow_allocator, sizeof(struct DoubleChain *),
                       "flow_allocator");
  klee_trace_param_ptr(sketch, sizeof(struct Sketch *), "sketch");

  klee_trace_param_u32(max_flows, "max_flows");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map **flows, struct Vector **flows_keys,
                           struct DoubleChain **flow_allocator,
                           struct Sketch **sketch, uint32_t max_flows,
                           uint32_t dev_count, unsigned int lcore_id,
                           vigor_time_t time) {
  loop_invariant_consume(flows, flows_keys, flow_allocator, sketch, max_flows,
                         dev_count, lcore_id, time);
  loop_reset(flows, flows_keys, flow_allocator, sketch, max_flows, dev_count,
             lcore_id, &time);
  loop_invariant_produce(flows, flows_keys, flow_allocator, sketch, max_flows,
                         dev_count, &lcore_id, &time);
}
#endif  // KLEE_VERIFICATION