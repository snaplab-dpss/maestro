#ifdef KLEE_VERIFICATION
#include "lib/models/verified/map-control.h"  //for map_reset
#endif                                        // KLEE_VERIFICATION
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_ethdev.h>

#include "lib/verified/double-chain.h"
#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/expirator.h"
#include "lib/verified/ether.h"

#include "nf.h"
#include "nf-util.h"
#include "nf-log.h"
#include "nf-parse.h"
#include "bridge_config.h"
#include "state.h"

struct nf_config config;

struct State *mac_tables;

int bridge_expire_entries(vigor_time_t time) {
  assert(time >= 0);  // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time;  // OK because of the two asserts
  vigor_time_t vigor_time_expiration = (vigor_time_t)config.expiration_time;
  vigor_time_t last_time = time_u - vigor_time_expiration * 1000;  // us to ns
  return expire_items_single_map(mac_tables->dyn_heap, mac_tables->dyn_keys,
                                 mac_tables->dyn_map, last_time);
}

int bridge_get_device(struct rte_ether_addr *dst, uint16_t src_device) {
#ifdef KLEE_VERIFICATION
  map_reset(mac_tables->dyn_map);  // simplify the traces for easy validation
#endif                             // KLEE_VERIFICATION

  int index = -1;
  int device = -1;
  int present = map_get(mac_tables->dyn_map, dst, &index);
  if (present) {
    struct DynamicValue *value = 0;
    vector_borrow(mac_tables->dyn_vals, index, (void **)&value);
    device = value->device;
    vector_return(mac_tables->dyn_vals, index, value);
    return device;
  }
  return -1;
}

void bridge_put_update_entry(struct rte_ether_addr *src, uint16_t src_device,
                             vigor_time_t time) {
  int index = -1;
  int present = map_get(mac_tables->dyn_map, src, &index);
  if (present) {
    dchain_rejuvenate_index(mac_tables->dyn_heap, index, time);
  } else {
    int allocated =
        dchain_allocate_new_index(mac_tables->dyn_heap, &index, time);
    if (!allocated) {
      NF_INFO("No more space in the dynamic table");
      return;
    }
    struct rte_ether_addr *key = 0;
    struct DynamicValue *value = 0;
    vector_borrow(mac_tables->dyn_keys, index, (void **)&key);
    vector_borrow(mac_tables->dyn_vals, index, (void **)&value);
    memcpy(key, src, sizeof(struct rte_ether_addr));
    value->device = src_device;
    map_put(mac_tables->dyn_map, key, index);
    // the other half of the key is in the map
    vector_return(mac_tables->dyn_keys, index, key);
    vector_return(mac_tables->dyn_vals, index, value);
  }
}

bool nf_init(void) {
  unsigned stat_capacity = 8192;  // Has to be power of 2
  unsigned capacity = config.dyn_capacity;
  assert(stat_capacity < CAPACITY_UPPER_LIMIT - 1);

  mac_tables = alloc_state(capacity, stat_capacity, rte_eth_dev_count_avail());
  if (mac_tables == NULL) {
    return false;
  }
  return true;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);

  bridge_expire_entries(now);
  bridge_put_update_entry(&rte_ether_header->s_addr, device, now);

  int forward_to = bridge_get_device(&rte_ether_header->d_addr, device);

  if (forward_to == -1) {
    return FLOOD_FRAME;
  }

  if (forward_to == -2) {
    NF_DEBUG("filtered frame");
    return device;
  }

  return forward_to;
}
