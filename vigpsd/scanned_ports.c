#include "scanned_ports.h"

#include <stdint.h>

bool ScannedPorts_eq(void *a, void *b) {
  struct ScannedPorts *sp1 = (struct ScannedPorts *)a;
  struct ScannedPorts *sp2 = (struct ScannedPorts *)b;

  if (sp1->src_ip != sp2->src_ip) {
    return false;
  }

  for (int bucket_id = 0; bucket_id < NUM_BUCKETS; bucket_id++) {
    if (sp1->buckets[bucket_id] != sp2->buckets[bucket_id]) {
      return false;
    }
  }

  return true;
}

void ScannedPorts_allocate(void *obj) {
  struct ScannedPorts *sp = obj;
  sp->src_ip = 0;
  for (int bucket_id = 0; bucket_id < NUM_BUCKETS; bucket_id++) {
    sp->buckets[bucket_id] = 0;
  }
  sp->total = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr ScannedPorts_descrs[] = {
  { offsetof(struct ScannedPorts, src_ip), sizeof(uint32_t), 0, "src_ip" },
  { offsetof(struct ScannedPorts, buckets), sizeof(ports_bucket_t),
    NUM_BUCKETS,                            "buckets" },
  { offsetof(struct ScannedPorts, total), sizeof(uint16_t), 0, "total" },
};
struct nested_field_descr ScannedPorts_nests[] = {};
unsigned ScannedPorts_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct ScannedPorts), "obj",
                              "ScannedPorts", TD_BOTH);
  for (int i = 0;
       i < sizeof(ScannedPorts_descrs) / sizeof(ScannedPorts_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, ScannedPorts_descrs[i].offset, ScannedPorts_descrs[i].width,
        ScannedPorts_descrs[i].count, ScannedPorts_descrs[i].name, TD_BOTH);
  }
  for (int i = 0;
       i < sizeof(ScannedPorts_nests) / sizeof(ScannedPorts_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, ScannedPorts_nests[i].base_offset, ScannedPorts_nests[i].offset,
        ScannedPorts_nests[i].width, ScannedPorts_nests[i].count,
        ScannedPorts_nests[i].name, TD_BOTH);
  }
  return klee_int("ScannedPorts_hash");
}

#else // KLEE_VERIFICATION

unsigned ScannedPorts_hash(void *obj) {
  struct ScannedPorts *sp = (struct ScannedPorts *)obj;
  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, sp->src_ip);
  for (int bucket_id = 0; bucket_id < NUM_BUCKETS; bucket_id++) {
    ports_bucket_t bucket_value = sp->buckets[bucket_id];
    unsigned long long result = __builtin_ia32_crc32di(
        hash, (unsigned long long)(bucket_value & 0xfffffffffff));
    hash = (unsigned int)(result & 0xffffffff);
  }
  hash = __builtin_ia32_crc32si(hash, sp->total);
  return hash;
}

#endif // KLEE_VERIFICATION
