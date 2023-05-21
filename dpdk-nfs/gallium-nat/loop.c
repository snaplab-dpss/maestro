#ifdef KLEE_VERIFICATION

#include <klee/klee.h>

#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/verified/vigor-time-control.h"
#include "loop.h"

void loop_reset(struct Map **table, struct Vector **flows,
                struct Vector **port_counter, int max_flows,
                uint32_t ext_ip, unsigned int lcore_id, vigor_time_t *time) {
  map_reset(*table);
  vector_reset(*flows);
  vector_reset(*port_counter);
  *time = restart_time();
}

void loop_invariant_consume(struct Map **table, struct Vector **flows,
                            struct Vector **port_counter, int max_flows,
                            uint32_t ext_ip, unsigned int lcore_id,
                            vigor_time_t time) {
  klee_trace_ret();
  klee_trace_param_ptr(table, sizeof(struct Map *), "table");
  klee_trace_param_ptr(flows, sizeof(struct Vector *), "flows");
  klee_trace_param_ptr(port_counter, sizeof(struct Vector *),
                       "port_counter");
  klee_trace_param_i32(max_flows, "max_flows");
  klee_trace_param_u32(ext_ip, "ext_ip");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map **table, struct Vector **flows,
                            struct Vector **port_counter, int max_flows,
                            uint32_t ext_ip, unsigned int *lcore_id,
                            vigor_time_t *time) {
  klee_trace_ret();
  klee_trace_param_ptr(table, sizeof(struct Map *), "table");
  klee_trace_param_ptr(flows, sizeof(struct Vector *), "flows");
  klee_trace_param_ptr(port_counter, sizeof(struct Vector *),
                       "port_counter");
  klee_trace_param_i32(max_flows, "max_flows");
  klee_trace_param_u32(ext_ip, "ext_ip");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map **table, struct Vector **flows,
                           struct Vector **port_counter, int max_flows,
                           uint32_t ext_ip, unsigned int lcore_id,
                           vigor_time_t time) {
  loop_invariant_consume(table, flows, port_counter, max_flows, ext_ip,
                         lcore_id, time);
  loop_reset(table, flows, port_counter, max_flows, ext_ip, lcore_id,
             &time);
  loop_invariant_produce(table, flows, port_counter, max_flows, ext_ip,
                         &lcore_id, &time);
}

#endif // KLEE_VERIFICATION