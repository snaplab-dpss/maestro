#include "stat_key.h"

#include <stdint.h>

bool StaticKey_eq(void *a, void *b) {
  struct StaticKey *id1 = (struct StaticKey *)a;
  struct StaticKey *id2 = (struct StaticKey *)b;

  bool addr_eq = rte_ether_addr_eq(&id1->addr, &id2->addr);
  return addr_eq AND(id1->device == id2->device);
}

void StaticKey_allocate(void *obj) {
  struct StaticKey *id = (struct StaticKey *)obj;

  id->addr.addr_bytes[0] = 0;
  id->addr.addr_bytes[1] = 0;
  id->addr.addr_bytes[2] = 0;
  id->addr.addr_bytes[3] = 0;
  id->addr.addr_bytes[4] = 0;
  id->addr.addr_bytes[5] = 0;

  id->device = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr StaticKey_descrs[] = {
    {offsetof(struct StaticKey, addr), sizeof(struct rte_ether_addr), 0,
     "addr"},
    {offsetof(struct StaticKey, device), sizeof(uint16_t), 0, "device"},
};
struct nested_field_descr StaticKey_nests[] = {
    {offsetof(struct StaticKey, addr),
     offsetof(struct rte_ether_addr, addr_bytes), sizeof(uint8_t), 6,
     "addr_bytes"},
};
unsigned StaticKey_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct StaticKey), "obj", "StaticKey",
                              TD_BOTH);
  for (int i = 0; i < sizeof(StaticKey_descrs) / sizeof(StaticKey_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, StaticKey_descrs[i].offset, StaticKey_descrs[i].width,
        StaticKey_descrs[i].count, StaticKey_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(StaticKey_nests) / sizeof(StaticKey_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, StaticKey_nests[i].base_offset, StaticKey_nests[i].offset,
        StaticKey_nests[i].width, StaticKey_nests[i].count,
        StaticKey_nests[i].name, TD_BOTH);
  }
  return klee_int("StaticKey_hash");
}

#else  // KLEE_VERIFICATION

unsigned StaticKey_hash(void *obj) {
  struct StaticKey *id = (struct StaticKey *)obj;

  unsigned hash = 0;
  unsigned addr_hash = rte_ether_addr_hash(&id->addr);
  hash = __builtin_ia32_crc32si(hash, addr_hash);
  hash = __builtin_ia32_crc32si(hash, id->device);
  return hash;
}

#endif  // KLEE_VERIFICATION
