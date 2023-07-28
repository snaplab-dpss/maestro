#include "flow.h"

#include <stdint.h>

bool flow_eq(void *a, void *b) {
  struct flow *id1 = (struct flow *)a;
  struct flow *id2 = (struct flow *)b;

  return (id1->src_port == id2->src_port) AND(id1->dst_port == id2->dst_port)
      AND(id1->src_ip == id2->src_ip) AND(id1->dst_ip == id2->dst_ip)
          AND(id1->protocol == id2->protocol);
}

void flow_allocate(void *obj) {
  struct flow *id = (struct flow *)obj;
  id->src_port = 0;
  id->dst_port = 0;
  id->src_ip = 0;
  id->dst_ip = 0;
  id->protocol = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr flow_descrs[] = {
    {offsetof(struct flow, src_port), sizeof(uint16_t), 0, "src_port"},
    {offsetof(struct flow, dst_port), sizeof(uint16_t), 0, "dst_port"},
    {offsetof(struct flow, src_ip), sizeof(uint32_t), 0, "src_ip"},
    {offsetof(struct flow, dst_ip), sizeof(uint32_t), 0, "dst_ip"},
    {offsetof(struct flow, protocol), sizeof(uint8_t), 0, "protocol"},
};
struct nested_field_descr flow_nests[] = {};
unsigned flow_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct flow), "obj", "flow", TD_BOTH);
  for (int i = 0; i < sizeof(flow_descrs) / sizeof(flow_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, flow_descrs[i].offset, flow_descrs[i].width, flow_descrs[i].count,
        flow_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(flow_nests) / sizeof(flow_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, flow_nests[i].base_offset, flow_nests[i].offset,
        flow_nests[i].width, flow_nests[i].count, flow_nests[i].name, TD_BOTH);
  }
  return klee_int("flow_hash");
}

#else  // KLEE_VERIFICATION

unsigned flow_hash(void *obj) {
  struct flow *id = (struct flow *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->src_port);
  hash = __builtin_ia32_crc32si(hash, id->dst_port);
  hash = __builtin_ia32_crc32si(hash, id->src_ip);
  hash = __builtin_ia32_crc32si(hash, id->dst_ip);
  hash = __builtin_ia32_crc32si(hash, id->protocol);
  return hash;
}

#endif  // KLEE_VERIFICATION
