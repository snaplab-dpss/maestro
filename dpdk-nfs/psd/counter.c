#include "counter.h"

#include <stdint.h>

bool counter_eq(void *a, void *b) {
  struct counter *id1 = (struct counter *)a;
  struct counter *id2 = (struct counter *)b;

  return (id1->value == id2->value);
}

void counter_allocate(void *obj) { (uintptr_t) obj; }

#ifdef KLEE_VERIFICATION
struct str_field_descr counter_descrs[] = {
    {offsetof(struct counter, value), sizeof(uint32_t), 0, "value"},
};
struct nested_field_descr counter_nests[] = {};
unsigned counter_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct counter), "obj", "counter",
                              TD_BOTH);
  for (int i = 0; i < sizeof(counter_descrs) / sizeof(counter_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, counter_descrs[i].offset, counter_descrs[i].width,
        counter_descrs[i].count, counter_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(counter_nests) / sizeof(counter_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, counter_nests[i].base_offset, counter_nests[i].offset,
        counter_nests[i].width, counter_nests[i].count, counter_nests[i].name,
        TD_BOTH);
  }
  return klee_int("counter_hash");
}

#else  // KLEE_VERIFICATION

unsigned counter_hash(void *obj) {
  struct counter *id = (struct counter *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

#endif  // KLEE_VERIFICATION
