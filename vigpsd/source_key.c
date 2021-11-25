#include "source_key.h"

#include <stdint.h>

bool SourceKey_eq(void *a, void *b) {
  struct SourceKey *sk1 = (struct SourceKey *)a;
  struct SourceKey *sk2 = (struct SourceKey *)b;

  return sk1->src_ip == sk2->src_ip && sk1->total == sk2->total;
}

void SourceKey_allocate(void *obj) {
  struct SourceKey *sk = obj;
  sk->src_ip = 0;
  sk->total = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr SourceKey_descrs[] = {
  { offsetof(struct SourceKey, src_ip), sizeof(uint32_t), 0, "src_ip" },
  { offsetof(struct SourceKey, total), sizeof(uint16_t), 0, "total" },
};
struct nested_field_descr SourceKey_nests[] = {};
unsigned SourceKey_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct SourceKey), "obj", "SourceKey",
                              TD_BOTH);
  for (int i = 0; i < sizeof(SourceKey_descrs) / sizeof(SourceKey_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, SourceKey_descrs[i].offset, SourceKey_descrs[i].width,
        SourceKey_descrs[i].count, SourceKey_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(SourceKey_nests) / sizeof(SourceKey_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, SourceKey_nests[i].base_offset, SourceKey_nests[i].offset,
        SourceKey_nests[i].width, SourceKey_nests[i].count,
        SourceKey_nests[i].name, TD_BOTH);
  }
  return klee_int("SourceKey_hash");
}

#else // KLEE_VERIFICATION

unsigned SourceKey_hash(void *obj) {
  struct SourceKey *sk = (struct SourceKey *)obj;
  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, sk->src_ip);
  hash = __builtin_ia32_crc32si(hash, sk->total);
  return hash;
}

#endif // KLEE_VERIFICATION
