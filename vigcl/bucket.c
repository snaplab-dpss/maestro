#include "bucket.h"

#include <stdint.h>

bool bucket_eq(void *a, void *b) {
  struct bucket *id1 = (struct bucket *)a;
  struct bucket *id2 = (struct bucket *)b;

  return (id1->value == id2->value);
}

void bucket_allocate(void *obj) { (uintptr_t) obj; }

#ifdef KLEE_VERIFICATION
struct str_field_descr bucket_descrs[] = {
  { offsetof(struct bucket, value), sizeof(uint32_t), 0, "value" },
};
struct nested_field_descr bucket_nests[] = {};
unsigned bucket_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct bucket), "obj", "bucket",
                              TD_BOTH);
  for (int i = 0; i < sizeof(bucket_descrs) / sizeof(bucket_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, bucket_descrs[i].offset, bucket_descrs[i].width,
        bucket_descrs[i].count, bucket_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(bucket_nests) / sizeof(bucket_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, bucket_nests[i].base_offset, bucket_nests[i].offset,
        bucket_nests[i].width, bucket_nests[i].count, bucket_nests[i].name,
        TD_BOTH);
  }
  return klee_int("bucket_hash");
}

#else // KLEE_VERIFICATION

unsigned bucket_hash(void *obj) {
  struct bucket *id = (struct bucket *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

#endif // KLEE_VERIFICATION
