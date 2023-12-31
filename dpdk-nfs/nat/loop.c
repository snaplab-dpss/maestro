#ifdef KLEE_VERIFICATION
#include <klee/klee.h>

#include "loop.h"

#include "lib/models/verified/vigor-time-control.h"
#include "lib/models/verified/double-chain-control.h"
#include "lib/models/verified/map-control.h"
#include "lib/models/verified/vector-control.h"
void loop_reset(struct Map** fm, struct Vector** fv, struct DoubleChain** heap,
                int max_flows, int start_port, uint32_t ext_ip,
                uint32_t nat_device, unsigned int lcore_id,
                vigor_time_t* time) {
  map_reset(*fm);
  vector_reset(*fv);
  dchain_reset(*heap, max_flows);
  *time = restart_time();
}
void loop_invariant_consume(struct Map** fm, struct Vector** fv,
                            struct DoubleChain** heap, int max_flows,
                            int start_port, uint32_t ext_ip,
                            uint32_t nat_device, unsigned int lcore_id,
                            vigor_time_t time) {
  klee_trace_ret();
  klee_trace_param_ptr(fm, sizeof(struct Map*), "fm");
  klee_trace_param_ptr(fv, sizeof(struct Vector*), "fv");
  klee_trace_param_ptr(heap, sizeof(struct DoubleChain*), "heap");
  klee_trace_param_i32(max_flows, "max_flows");
  klee_trace_param_i32(start_port, "start_port");
  klee_trace_param_u32(ext_ip, "ext_ip");
  klee_trace_param_u32(nat_device, "nat_device");
  klee_trace_param_i32(lcore_id, "lcore_id");
  klee_trace_param_i64(time, "time");
}
void loop_invariant_produce(struct Map** fm, struct Vector** fv,
                            struct DoubleChain** heap, int max_flows,
                            int start_port, uint32_t ext_ip,
                            uint32_t nat_device, unsigned int* lcore_id,
                            vigor_time_t* time) {
  klee_trace_ret();
  klee_trace_param_ptr(fm, sizeof(struct Map*), "fm");
  klee_trace_param_ptr(fv, sizeof(struct Vector*), "fv");
  klee_trace_param_ptr(heap, sizeof(struct DoubleChain*), "heap");
  klee_trace_param_i32(max_flows, "max_flows");
  klee_trace_param_i32(start_port, "start_port");
  klee_trace_param_u32(ext_ip, "ext_ip");
  klee_trace_param_u32(nat_device, "nat_device");
  klee_trace_param_ptr(lcore_id, sizeof(unsigned int), "lcore_id");
  klee_trace_param_ptr(time, sizeof(vigor_time_t), "time");
}
void loop_iteration_border(struct Map** fm, struct Vector** fv,
                           struct DoubleChain** heap, int max_flows,
                           int start_port, uint32_t ext_ip, uint32_t nat_device,
                           unsigned int lcore_id, vigor_time_t time) {
  loop_invariant_consume(fm, fv, heap, max_flows, start_port, ext_ip,
                         nat_device, lcore_id, time);
  loop_reset(fm, fv, heap, max_flows, start_port, ext_ip, nat_device, lcore_id,
             &time);
  loop_invariant_produce(fm, fv, heap, max_flows, start_port, ext_ip,
                         nat_device, &lcore_id, &time);
}
#endif  // KLEE_VERIFICATION