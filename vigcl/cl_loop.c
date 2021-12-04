#include <klee/klee.h>

#include "cl_loop.h"

#include "libvig/models/verified/vigor-time-control.h"
#include "libvig/models/verified/double-chain-control.h"
#include "libvig/models/verified/map-control.h"
#include "libvig/models/verified/vector-control.h"

void loop_reset(struct Map **flows, struct Vector **flows_keys,
                struct DoubleChain **flow_allocator, struct Map **clients,
                struct Vector **clients_keys, struct Vector **clients_buckets,
                struct DoubleChain *client_allocator[SKETCH_HASHES],
                uint32_t max_flows, uint32_t sketch_capacity,
                uint32_t dev_count, unsigned int lcore_id, vigor_time_t *time) {
  map_reset(*flows);
  vector_reset(*flows_keys);
  dchain_reset(*flow_allocator, max_flows);

  map_reset(*clients);
  vector_reset(*clients_keys);
  vector_reset(*clients_buckets);

  for (int i = 0; i < SKETCH_HASHES; i++) {
    dchain_reset(client_allocator[i], sketch_capacity);
  }

  *time = restart_time();
}

void loop_invariant_consume(struct Map **flows, struct Vector **flows_keys,
                            struct DoubleChain **flow_allocator,
                            struct Map **clients, struct Vector **clients_keys,
                            struct Vector **clients_buckets,
                            struct DoubleChain *client_allocator[SKETCH_HASHES],
                            uint32_t max_flows, uint32_t sketch_capacity,
                            uint32_t dev_count, unsigned int lcore_id,
                            vigor_time_t time) {
  klee_trace_ret();

  klee_trace_param_ptr(flows, sizeof(struct Map *), "flows");
  klee_trace_param_ptr(flows_keys, sizeof(struct Vector *), "flows_keys");
  klee_trace_param_ptr(flow_allocator, sizeof(struct DoubleChain *),
                       "flow_allocator");

  klee_trace_param_ptr(clients, sizeof(struct Map *), "clients");
  klee_trace_param_ptr(clients_keys, sizeof(struct Vector *), "clients_keys");
  klee_trace_param_ptr(clients_buckets, sizeof(struct Vector *),
                       "clients_buckets");

  for (int i = 0; i < SKETCH_HASHES; i++) {
    klee_trace_param_ptr(&client_allocator[i], sizeof(struct DoubleChain *),
                         "client_allocator");
  }

  klee_trace_param_u32(max_flows, "max_flows");
  klee_trace_param_u32(sketch_capacity, "sketch_capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}

void loop_invariant_produce(struct Map **flows, struct Vector **flows_keys,
                            struct DoubleChain **flow_allocator,
                            struct Map **clients, struct Vector **clients_keys,
                            struct Vector **clients_buckets,
                            struct DoubleChain *client_allocator[SKETCH_HASHES],
                            uint32_t max_flows, uint32_t sketch_capacity,
                            uint32_t dev_count, unsigned int *lcore_id,
                            vigor_time_t *time) {
  klee_trace_ret();

  klee_trace_param_ptr(flows, sizeof(struct Map *), "flows");
  klee_trace_param_ptr(flows_keys, sizeof(struct Vector *), "flows_keys");
  klee_trace_param_ptr(flow_allocator, sizeof(struct DoubleChain *),
                       "flow_allocator");

  klee_trace_param_ptr(clients, sizeof(struct Map *), "clients");
  klee_trace_param_ptr(clients_keys, sizeof(struct Vector *), "clients_keys");
  klee_trace_param_ptr(clients_buckets, sizeof(struct Vector *),
                       "clients_buckets");

  for (int i = 0; i < SKETCH_HASHES; i++) {
    klee_trace_param_ptr(&client_allocator[i], sizeof(struct DoubleChain *),
                         "client_allocator");
  }

  klee_trace_param_u32(max_flows, "max_flows");
  klee_trace_param_u32(sketch_capacity, "sketch_capacity");
  klee_trace_param_u32(dev_count, "dev_count");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}

void loop_iteration_border(struct Map **flows, struct Vector **flows_keys,
                           struct DoubleChain **flow_allocator,
                           struct Map **clients, struct Vector **clients_keys,
                           struct Vector **clients_buckets,
                           struct DoubleChain **client_allocator,
                           uint32_t max_flows, uint32_t sketch_capacity,
                           uint32_t dev_count, unsigned int lcore_id,
                           vigor_time_t time) {
  loop_invariant_consume(flows, flows_keys, flow_allocator, clients,
                         clients_keys, clients_buckets, client_allocator,
                         max_flows, sketch_capacity, dev_count, lcore_id, time);
  loop_reset(flows, flows_keys, flow_allocator, clients, clients_keys,
             clients_buckets, client_allocator, max_flows, sketch_capacity,
             dev_count, lcore_id, &time);
  loop_invariant_produce(flows, flows_keys, flow_allocator, clients,
                         clients_keys, clients_buckets, client_allocator,
                         max_flows, sketch_capacity, dev_count, &lcore_id,
                         &time);
}
