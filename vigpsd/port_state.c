#include "port_state.h"

#include <stdint.h>

bool port_state_state_eq(void *a, void *b) {
  struct port_state *id1 = (struct port_state *)a;
  struct port_state *id2 = (struct port_state *)b;

  return (id1->touched == id2->touched);
}

void port_state_allocate(void *obj) { (uintptr_t) obj; }

#ifdef KLEE_VERIFICATION
struct str_field_descr port_state_descrs[] = {
  { offsetof(struct port_state, addr), sizeof(uint16_t), 0, "port_state" },
};
struct nested_field_descr port_state_nests[] = {};
unsigned port_state_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct port_state), "obj",
                              "port_state", TD_BOTH);
  for (int i = 0; i < sizeof(port_state_descrs) / sizeof(port_state_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, port_state_descrs[i].offset, port_state_descrs[i].width,
        port_state_descrs[i].count, port_state_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(port_state_nests) / sizeof(port_state_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, port_state_nests[i].base_offset, port_state_nests[i].offset,
        port_state_nests[i].width, port_state_nests[i].count,
        port_state_nests[i].name, TD_BOTH);
  }
  return klee_int("port_state_hash");
}

#else // KLEE_VERIFICATION

unsigned port_state_hash(void *obj) {
  struct port_state *id = (struct port_state *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, (unsigned)id->touched);
  return hash;
}

#endif // KLEE_VERIFICATION
