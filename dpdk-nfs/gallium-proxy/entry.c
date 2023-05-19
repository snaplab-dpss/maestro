#include "entry.h"

bool entry_eq(void *a, void *b) {
  struct Entry *id1 = (struct Entry *)a;
  struct Entry *id2 = (struct Entry *)b;

  return id1->port == id2->port;
}

void entry_allocate(void *obj) {
  struct Entry *id = (struct Entry *)obj;
  id->port = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr entry_descrs[] = {
  { offsetof(struct Entry, port), sizeof(uint16_t), 0, "port" },
};

struct nested_field_descr entry_nests[] = {};

unsigned entry_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct Entry), "obj", "Entry",
                              TD_BOTH);
  for (int i = 0; i < sizeof(entry_descrs) / sizeof(entry_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, entry_descrs[i].offset, entry_descrs[i].width,
        entry_descrs[i].count, entry_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(entry_nests) / sizeof(entry_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, entry_nests[i].base_offset, entry_nests[i].offset,
        entry_nests[i].width, entry_nests[i].count, entry_nests[i].name,
        TD_BOTH);
  }
  return klee_int("Entry_hash");
}

#else // KLEE_VERIFICATION

unsigned entry_hash(void *obj) {
  struct Entry *id = (struct Entry *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->port);
  return hash;
}

#endif // KLEE_VERIFICATION
