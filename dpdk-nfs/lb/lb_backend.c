#include "lb_backend.h"

#include <stdint.h>

bool LoadBalancedBackend_eq(void* a, void* b) {
  struct LoadBalancedBackend* id1 = (struct LoadBalancedBackend*)a;
  struct LoadBalancedBackend* id2 = (struct LoadBalancedBackend*)b;

  bool mac_eq = rte_ether_addr_eq(&id1->mac, &id2->mac);
  return (id1->nic == id2->nic) AND mac_eq AND(id1->ip == id2->ip);
}

void LoadBalancedBackend_allocate(void* obj) {
  struct LoadBalancedBackend* id = (struct LoadBalancedBackend*)obj;
  id->nic = 0;

  id->mac.addr_bytes[0] = 0;
  id->mac.addr_bytes[1] = 0;
  id->mac.addr_bytes[2] = 0;
  id->mac.addr_bytes[3] = 0;
  id->mac.addr_bytes[4] = 0;
  id->mac.addr_bytes[5] = 0;

  id->ip = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr LoadBalancedBackend_descrs[] = {
    {offsetof(struct LoadBalancedBackend, nic), sizeof(uint16_t), 0, "nic"},
    {offsetof(struct LoadBalancedBackend, mac), sizeof(struct rte_ether_addr),
     0, "mac"},
    {offsetof(struct LoadBalancedBackend, ip), sizeof(uint32_t), 0, "ip"},
};
struct nested_field_descr LoadBalancedBackend_nests[] = {
    {offsetof(struct LoadBalancedBackend, mac),
     offsetof(struct rte_ether_addr, addr_bytes), sizeof(uint8_t), 6,
     "addr_bytes"},
};
unsigned LoadBalancedBackend_hash(void* obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct LoadBalancedBackend), "obj",
                              "LoadBalancedBackend", TD_BOTH);
  for (int i = 0; i < sizeof(LoadBalancedBackend_descrs) /
                          sizeof(LoadBalancedBackend_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, LoadBalancedBackend_descrs[i].offset,
        LoadBalancedBackend_descrs[i].width,
        LoadBalancedBackend_descrs[i].count, LoadBalancedBackend_descrs[i].name,
        TD_BOTH);
  }
  for (int i = 0; i < sizeof(LoadBalancedBackend_nests) /
                          sizeof(LoadBalancedBackend_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, LoadBalancedBackend_nests[i].base_offset,
        LoadBalancedBackend_nests[i].offset, LoadBalancedBackend_nests[i].width,
        LoadBalancedBackend_nests[i].count, LoadBalancedBackend_nests[i].name,
        TD_BOTH);
  }
  return klee_int("LoadBalancedBackend_hash");
}

#else  // KLEE_VERIFICATION

unsigned LoadBalancedBackend_hash(void* obj) {
  struct LoadBalancedBackend* id = (struct LoadBalancedBackend*)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->nic);
  unsigned mac_hash = rte_ether_addr_hash(&id->mac);
  hash = __builtin_ia32_crc32si(hash, mac_hash);
  hash = __builtin_ia32_crc32si(hash, id->ip);
  return hash;
}

#endif  // KLEE_VERIFICATION
