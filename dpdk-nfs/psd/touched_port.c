#include "touched_port.h"

#include <stdint.h>

bool touched_port_eq(void *a, void *b) {
  struct TouchedPort *tp1 = (struct TouchedPort *)a;
  struct TouchedPort *tp2 = (struct TouchedPort *)b;
  return tp1->src == tp2->src && tp1->port == tp2->port;
}

void touched_port_allocate(void *obj) {
  struct TouchedPort *tp = (struct TouchedPort *)obj;
  tp->src = 0;
  tp->port = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr touched_port_descrs[] = {
    {offsetof(struct TouchedPort, src), sizeof(uint32_t), 0, "src"},
    {offsetof(struct TouchedPort, port), sizeof(uint16_t), 0, "port"},
};
struct nested_field_descr touched_port_nests[] = {};
unsigned touched_port_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct TouchedPort), "obj",
                              "TouchedPort", TD_BOTH);
  for (int i = 0;
       i < sizeof(touched_port_descrs) / sizeof(touched_port_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, touched_port_descrs[i].offset, touched_port_descrs[i].width,
        touched_port_descrs[i].count, touched_port_descrs[i].name, TD_BOTH);
  }
  for (int i = 0;
       i < sizeof(touched_port_nests) / sizeof(touched_port_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, touched_port_nests[i].base_offset, touched_port_nests[i].offset,
        touched_port_nests[i].width, touched_port_nests[i].count,
        touched_port_nests[i].name, TD_BOTH);
  }
  return klee_int("port_hash");
}

#else  // KLEE_VERIFICATION

unsigned touched_port_hash(void *obj) {
  struct TouchedPort *tp = (struct TouchedPort *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, tp->src);
  hash = __builtin_ia32_crc32si(hash, tp->port);
  return hash;
}

#endif  // KLEE_VERIFICATION
