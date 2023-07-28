#ifdef KLEE_VERIFICATION
#include <klee/klee.h>

#include "psd_loop.h"

#include "lib/models/verified/vigor-time-control.h"
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"

void loop_reset(struct Map **srcs, struct Vector **srcs_keys,
                struct Vector **touched_ports_counter,
                struct DoubleChain **allocator, struct Map **ports,
                struct Vector **ports_key, uint32_t capacity,
                uint32_t max_ports, uint32_t dev_count, unsigned int lcore_id,
                vigor_time_t *time) {
  map_reset(*srcs);
  vector_reset(*srcs_keys);
  vector_reset(*touched_ports_counter);
  dchain_reset(*allocator, capacity);

  map_reset(*ports);
  vector_reset(*ports_key);

  *time = restart_time();
}

void loop_invariant_consume(struct Map **srcs, struct Vector **srcs_keys,
                            struct Vector **touched_ports_counter,
                            struct DoubleChain **allocator, struct Map **ports,
                            struct Vector **ports_key, uint32_t capacity,
                            uint32_t max_ports, uint32_t dev_count,
                            unsigned int lcore_id, vigor_time_t time) {
  klee_trace_ret();

  klee_trace_param_ptr(srcs, sizeof(struct Map *), "srcs");
  klee_trace_param_ptr(srcs_keys, sizeof(struct Vector *), "srcs_keys");
  klee_trace_param_ptr(touched_ports_counter, sizeof(struct Vector *),
                       "touched_ports_counter");
  klee_trace_param_ptr(allocator, sizeof(struct DoubleChain *), "allocator");

  klee_trace_param_ptr(ports, sizeof(struct Vector *), "ports");
  klee_trace_param_ptr(ports_key, sizeof(struct Vector *), "ports_key");

  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map **srcs, struct Vector **srcs_keys,
                            struct Vector **touched_ports_counter,
                            struct DoubleChain **allocator, struct Map **ports,
                            struct Vector **ports_key, uint32_t capacity,
                            uint32_t max_ports, uint32_t dev_count,
                            unsigned int *lcore_id, vigor_time_t *time) {
  klee_trace_ret();

  klee_trace_param_ptr(srcs, sizeof(struct Map *), "srcs");
  klee_trace_param_ptr(srcs_keys, sizeof(struct Vector *), "srcs_keys");
  klee_trace_param_ptr(touched_ports_counter, sizeof(struct Vector *),
                       "touched_ports_counter");
  klee_trace_param_ptr(allocator, sizeof(struct DoubleChain *), "allocator");

  klee_trace_param_ptr(ports, sizeof(struct Vector *), "ports");
  klee_trace_param_ptr(ports_key, sizeof(struct Vector *), "ports_key");

  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map **srcs, struct Vector **srcs_keys,
                           struct Vector **touched_ports_counter,
                           struct DoubleChain **allocator, struct Map **ports,
                           struct Vector **ports_key, uint32_t capacity,
                           uint32_t max_ports, uint32_t dev_count,
                           unsigned int lcore_id, vigor_time_t time) {
  loop_invariant_consume(srcs, srcs_keys, touched_ports_counter, allocator,
                         ports, ports_key, capacity, max_ports, dev_count,
                         lcore_id, time);
  loop_reset(srcs, srcs_keys, touched_ports_counter, allocator, ports,
             ports_key, capacity, max_ports, dev_count, lcore_id, &time);
  loop_invariant_produce(srcs, srcs_keys, touched_ports_counter, allocator,
                         ports, ports_key, capacity, max_ports, dev_count,
                         &lcore_id, &time);
}
#endif  // KLEE_VERIFICATION