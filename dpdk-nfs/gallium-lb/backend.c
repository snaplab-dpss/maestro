#include "backend.h"

bool backend_eq(void *a, void *b) {
  struct Backend *id1 = (struct Backend *)a;
  struct Backend *id2 = (struct Backend *)b;

  return id1->ip == id2->ip;
}

void backend_allocate(void *obj) {
  struct Backend *id = (struct Backend *)obj;
  id->ip = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr backend_descrs[] = {
  { offsetof(struct Backend, ip), sizeof(uint32_t), 0, "ip" },
};

struct nested_field_descr backend_nests[] = {};

unsigned backend_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct Backend), "obj", "Backend",
                              TD_BOTH);
  for (int i = 0; i < sizeof(backend_descrs) / sizeof(backend_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, backend_descrs[i].offset, backend_descrs[i].width,
        backend_descrs[i].count, backend_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(backend_nests) / sizeof(backend_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, backend_nests[i].base_offset, backend_nests[i].offset,
        backend_nests[i].width, backend_nests[i].count, backend_nests[i].name,
        TD_BOTH);
  }
  return klee_int("Backend_hash");
}

#else // KLEE_VERIFICATION

unsigned backend_hash(void *obj) {
  struct Backend *id = (struct Backend *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->ip);
  return hash;
}

#endif // KLEE_VERIFICATION
