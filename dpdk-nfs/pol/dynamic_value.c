#include "dynamic_value.h"

#include <stdint.h>

bool DynamicValue_eq(void* a, void* b) {
  struct DynamicValue* id1 = (struct DynamicValue*)a;
  struct DynamicValue* id2 = (struct DynamicValue*)b;

  return (id1->bucket_size == id2->bucket_size)
      AND(id1->bucket_time == id2->bucket_time);
}

void DynamicValue_allocate(void* obj) {
  struct DynamicValue* id = (struct DynamicValue*)obj;
  id->bucket_size = 0;
  id->bucket_time = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr DynamicValue_descrs[] = {
    {offsetof(struct DynamicValue, bucket_size), sizeof(uint64_t), 0,
     "bucket_size"},
    {offsetof(struct DynamicValue, bucket_time), sizeof(int64_t), 0,
     "bucket_time"},
};
struct nested_field_descr DynamicValue_nests[] = {

};
unsigned DynamicValue_hash(void* obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct DynamicValue), "obj",
                              "DynamicValue", TD_BOTH);
  for (int i = 0;
       i < sizeof(DynamicValue_descrs) / sizeof(DynamicValue_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, DynamicValue_descrs[i].offset, DynamicValue_descrs[i].width,
        DynamicValue_descrs[i].count, DynamicValue_descrs[i].name, TD_BOTH);
  }
  for (int i = 0;
       i < sizeof(DynamicValue_nests) / sizeof(DynamicValue_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, DynamicValue_nests[i].base_offset, DynamicValue_nests[i].offset,
        DynamicValue_nests[i].width, DynamicValue_nests[i].count,
        DynamicValue_nests[i].name, TD_BOTH);
  }
  return klee_int("DynamicValue_hash");
}

#else  // KLEE_VERIFICATION

unsigned DynamicValue_hash(void* obj) {
  struct DynamicValue* id = (struct DynamicValue*)obj;

  unsigned hash = 0;
  hash = (unsigned int)(__builtin_ia32_crc32di(
                            hash, (unsigned long long)(id->bucket_size &
                                                       0xfffffffffff)) &
                        0xffffffff);
  hash = (unsigned int)(__builtin_ia32_crc32di(
                            hash, (unsigned long long)(id->bucket_time &
                                                       0xfffffffffff)) &
                        0xffffffff);
  return hash;
}

#endif  // KLEE_VERIFICATION
