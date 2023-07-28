#include "client.h"

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#ifdef KLEE_VERIFICATION
struct str_field_descr client_descrs[] = {
    {offsetof(struct client, src_ip), sizeof(uint32_t), 0, "src_ip"},
    {offsetof(struct client, dst_ip), sizeof(uint32_t), 0, "dst_ip"},
};
struct nested_field_descr client_nests[] = {};

unsigned client_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct client), "obj", "client",
                              TD_BOTH);
  for (int i = 0; i < sizeof(client_descrs) / sizeof(client_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, client_descrs[i].offset, client_descrs[i].width,
        client_descrs[i].count, client_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(client_nests) / sizeof(client_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, client_nests[i].base_offset, client_nests[i].offset,
        client_nests[i].width, client_nests[i].count, client_nests[i].name,
        TD_BOTH);
  }
  return klee_int("ip_addr_hash");
}
#else  // KLEE_VERIFICATION

unsigned client_hash(void *obj) {
  struct client *id = (struct client *)obj;
  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->src_ip);
  hash = __builtin_ia32_crc32si(hash, id->dst_ip);
  return hash;
}

#endif  // KLEE_VERIFICATION
