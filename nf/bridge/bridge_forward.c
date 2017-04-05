#include <inttypes.h>
#include <assert.h>

// DPDK uses these but doesn't include them. :|
#include <linux/limits.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "lib/nf_forward.h"
#include "lib/nf_util.h"
#include "lib/nf_log.h"
#include "bridge_config.h"

struct bridge_config config;

struct Map {
  int* busybits;
  void** keyps;
  int* khs;
  int* chns;
  int* vals;
  int capacity;
  int size;
};

struct StaticKey {
  struct ether_addr addr;
  uint8_t device;
};

struct DynamicFilterTable {
  struct Map map;
  struct DoubleChain* heap;
  struct ether_addr* keys;
  int* devices;
};

struct StaticFilterTable {
  struct Map map;
  struct StaticKey* keys;
};

struct StaticFilterTable static_ft;
struct DynamicFilterTable dynamic_ft;

int ether_addr_eq(struct ether_addr* a,
                  struct ether_addr* b) {
  return 0 == memcmp(a->addr_bytes,
                     b->addr_bytes,
                     6);
}

int static_key_eq(struct StaticKey* a,
                  struct StaticKey* b) {
  return a->device == b->device && ether_addr_eq(&a->addr, &b->addr);

}

int ether_addr_hash(struct ether_addr* addr) {
  return (int)((*(uint32_t*)addr->addr_bytes) ^
               (*(uint32_t*)(addr->addr_bytes + 2)));
}

int static_key_hash(struct StaticKey* k) {
  return (ether_addr_hash(&k->addr) << 2) ^ k->device;
}

int bridge_expire_entries(uint32_t time) {
  int count = 0;
  int index = -1;
  void *trash;
  if (time < config.expiration_time) return 0;
  uint32_t min_time = time - config.expiration_time;
  while (dchain_expire_one_index(dynamic_ft.heap, &index, min_time)) {
    int hash = ether_addr_hash(&dynamic_ft.keys[index]);
    map_erase(dynamic_ft.map.busybits,
              dynamic_ft.map.keyps,
              dynamic_ft.map.khs,
              dynamic_ft.map.chns,
              &dynamic_ft.keys[index],
              ether_addr_eq,
              hash,
              dynamic_ft.map.capacity,
              &trash);
    ++count;
    --dynamic_ft.map.size;
  }
  return count;
}

int bridge_get_device(struct ether_addr* dst,
                      uint8_t src_device) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, dst, sizeof(struct ether_addr));
  k.device = src_device;
  int hash = static_key_hash(&k);
  int present = map_get(static_ft.map.busybits,
                        static_ft.map.keyps,
                        static_ft.map.khs,
                        static_ft.map.chns,
                        static_ft.map.vals,
                        &k,
                        static_key_eq,
                        hash,
                        &device,
                        static_ft.map.capacity);
  if (present) {
    return device;
  }

  int index = -1;
  hash = ether_addr_hash(dst);
  present = map_get(dynamic_ft.map.busybits,
                    dynamic_ft.map.keyps,
                    dynamic_ft.map.khs,
                    dynamic_ft.map.chns,
                    dynamic_ft.map.vals,
                    dst,
                    ether_addr_eq,
                    hash,
                    &index,
                    dynamic_ft.map.capacity);
  if (present) {
    return dynamic_ft.devices[index];
  }
  return -1;
}

void bridge_put_update_entry(struct ether_addr* src,
                            uint8_t src_device,
                            uint32_t time) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, src, sizeof(struct ether_addr));
  k.device = src_device;
  int hash = static_key_hash(&k);
  int present = map_get(static_ft.map.busybits,
                        static_ft.map.keyps,
                        static_ft.map.khs,
                        static_ft.map.chns,
                        static_ft.map.vals,
                        &k,
                        static_key_eq,
                        hash,
                        &device,
                        static_ft.map.capacity);
  if (present) {
    // Static entry does not need updating
    return;
  }

  int index = -1;
  hash = ether_addr_hash(src);
  present = map_get(dynamic_ft.map.busybits,
                    dynamic_ft.map.keyps,
                    dynamic_ft.map.khs,
                    dynamic_ft.map.chns,
                    dynamic_ft.map.vals,
                    src,
                    ether_addr_eq,
                    hash,
                    &index,
                    dynamic_ft.map.capacity);
  if (present) {
    dchain_rejuvenate_index(dynamic_ft.heap, index, time);
  } else {
    int allocated = dchain_allocate_new_index(dynamic_ft.heap,
                                              &index,
                                              time);
    if (!allocated) {
      NF_INFO("No more space in the dynamic table");
      return;
    }
    memcpy(&dynamic_ft.keys[index], src, sizeof(struct ether_addr));
    map_put(dynamic_ft.map.busybits,
            dynamic_ft.map.keyps,
            dynamic_ft.map.khs,
            dynamic_ft.map.chns,
            dynamic_ft.map.vals,
            &dynamic_ft.keys[index],
            hash, index,
            dynamic_ft.map.capacity);
    dynamic_ft.devices[index] = device;
    ++dynamic_ft.map.size;
  }
}

void nf_core_init(void)
{
  int capacity = config.dyn_capacity;
  static_ft.map.busybits = malloc(capacity*sizeof(int));
  static_ft.map.keyps    = malloc(capacity*sizeof(void*));
  static_ft.map.khs      = malloc(capacity*sizeof(int));
  static_ft.map.chns     = malloc(capacity*sizeof(int));
  static_ft.map.vals     = malloc(capacity*sizeof(int));
  static_ft.map.capacity = capacity;
  static_ft.map.size = 0;
  map_initialize(static_ft.map.busybits,
                 static_key_eq,
                 static_ft.map.keyps,
                 static_ft.map.khs,
                 static_ft.map.chns,
                 static_ft.map.vals,
                 static_ft.map.capacity);
  static_ft.keys          = malloc(capacity*sizeof(struct StaticKey));

  dynamic_ft.map.busybits = malloc(capacity*sizeof(int));
  dynamic_ft.map.keyps    = malloc(capacity*sizeof(void*));
  dynamic_ft.map.khs      = malloc(capacity*sizeof(int));
  dynamic_ft.map.chns     = malloc(capacity*sizeof(int));
  dynamic_ft.map.vals     = malloc(capacity*sizeof(int));
  dynamic_ft.map.capacity = capacity;
  dynamic_ft.map.size = 0;
  map_initialize(dynamic_ft.map.busybits,
                 ether_addr_eq,
                 dynamic_ft.map.keyps,
                 dynamic_ft.map.khs,
                 dynamic_ft.map.chns,
                 dynamic_ft.map.vals,
                 dynamic_ft.map.capacity);
  dchain_allocate(dynamic_ft.map.capacity,
                  &dynamic_ft.heap);
  dynamic_ft.keys         = malloc(capacity*sizeof(struct ether_addr));
  dynamic_ft.devices      = malloc(capacity*sizeof(int));
}

int nf_core_process(uint8_t device,
                    struct rte_mbuf* mbuf,
                    uint32_t now)
{
  struct ether_hdr* ether_header = nf_get_mbuf_ether_header(mbuf);

  bridge_expire_entries(now);
  bridge_put_update_entry(&ether_header->s_addr, device, now);

  int dst_device = bridge_get_device(&ether_header->d_addr,
                                     device);

  if (dst_device == -1) {
    return FLOOD_FRAME;
  }

  if (dst_device == -2) {
    NF_DEBUG("filtered frame");
    return device;
  }

  return dst_device;
}

void nf_config_init(int argc, char** argv) {
  bridge_config_init(&config, argc, argv);
}

void nf_config_cmdline_print_usage(void) {
  bridge_config_cmdline_print_usage();
}

void nf_print_config() {
  bridge_print_config(&config);
}
