#ifdef KLEE_VERIFICATION

#include "loop.h"

#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
#include "lib/models/verified/vigor-time-control.h"

#include <klee/klee.h>

void loop_reset(struct Map **table, struct Vector **flows,
                struct Vector **flows_counter, struct Vector **backends,
                struct Vector **backends_counter, unsigned int lcore_id,
                vigor_time_t *time) {
  map_reset(*table);
  vector_reset(*flows);
  vector_reset(*flows_counter);
  vector_reset(*backends);
  vector_reset(*backends_counter);
  *time = restart_time();
}

void loop_invariant_consume(struct Map **table, struct Vector **flows,
                            struct Vector **flows_counter,
                            struct Vector **backends,
                            struct Vector **backends_counter,
                            unsigned int lcore_id, vigor_time_t time) {
  klee_trace_ret();
  klee_trace_param_ptr(table, sizeof(struct Map *), "table");
  klee_trace_param_ptr(flows, sizeof(struct Vector *), "flows");
  klee_trace_param_ptr(flows_counter, sizeof(struct Vector *), "flows_counter");
  klee_trace_param_ptr(backends, sizeof(struct Vector *), "backends");
  klee_trace_param_ptr(backends_counter, sizeof(struct Vector *),
                       "backends_counter");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map **table, struct Vector **flows,
                            struct Vector **flows_counter,
                            struct Vector **backends,
                            struct Vector **backends_counter,
                            unsigned int *lcore_id, vigor_time_t *time) {
  klee_trace_ret();
  klee_trace_param_ptr(table, sizeof(struct Map *), "table");
  klee_trace_param_ptr(flows, sizeof(struct Vector *), "flows");
  klee_trace_param_ptr(flows_counter, sizeof(struct Vector *), "flows_counter");
  klee_trace_param_ptr(backends, sizeof(struct Vector *), "backends");
  klee_trace_param_ptr(backends_counter, sizeof(struct Vector *),
                       "backends_counter");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map **table, struct Vector **flows,
                           struct Vector **flows_counter,
                           struct Vector **backends,
                           struct Vector **backends_counter,
                           unsigned int lcore_id, vigor_time_t time) {
  loop_invariant_consume(table, flows, flows_counter, backends,
                         backends_counter, lcore_id, time);
  loop_reset(table, flows, flows_counter, backends, backends_counter, lcore_id,
             &time);
  loop_invariant_produce(table, flows, flows_counter, backends,
                         backends_counter, &lcore_id, &time);
}

#endif // KLEE_VERIFICATION