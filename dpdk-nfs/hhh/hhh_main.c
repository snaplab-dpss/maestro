#include <stdint.h>
#include <assert.h>

#include <rte_byteorder.h>

#include "lib/verified/expirator.h"

#include "nf.h"
#include "nf-log.h"
#include "nf-util.h"

#include "hhh_config.h"
#include "hhh_state.h"

#define SWAP_ENDIANNESS_32_BIT(n)                       \
  (((n >> 24) & 0x000000ff) | ((n >> 8) & 0x0000ff00) | \
   ((n << 8) & 0x00ff0000) | ((n << 24) & 0xff000000))

struct nf_config config;
struct State *state;

bool nf_init(void) {
  uint64_t link_capacity = config.link_capacity;
  uint8_t threshold = config.threshold;
  uint32_t subnets_mask = config.subnets_mask;
  unsigned capacity = config.dyn_capacity;
  uint32_t dev_count = rte_eth_dev_count_avail();

  state =
      alloc_state(link_capacity, threshold, subnets_mask, capacity, dev_count);

  return state != NULL;
}

int64_t expire_entries(vigor_time_t time) {
  assert(time >= 0);  // we don't support the past
  vigor_time_t exp_time =
      VIGOR_TIME_SECONDS_MULTIPLIER * config.burst / state->threshold_rate;
  uint64_t time_u = (uint64_t)time;
  // OK because time >= config.burst / threshold_rate >= 0
  vigor_time_t min_time = time_u - exp_time;
  int64_t freed = 0;
  for (int i = 0; i < state->n_subnets; i++) {
    freed += expire_items_single_map(state->allocators[i], state->subnets[i],
                                     state->subnet_indexers[i], min_time);
  }
  return freed;
}

bool allocate(uint32_t masked_src, int i_subnet, uint16_t size,
              vigor_time_t time) {
  int index = -1;

  int allocated =
      dchain_allocate_new_index(state->allocators[i_subnet], &index, time);

  if (!allocated) {
    // Nothing we can do...
    NF_DEBUG("No more space in the HHH subnet match tables");
    return false;
  }

  uint32_t *key = NULL;
  struct DynamicValue *value = NULL;

  vector_borrow(state->subnets[i_subnet], index, (void **)&key);
  vector_borrow(state->subnet_buckets[i_subnet], index, (void **)&value);

  *key = masked_src;

  assert(config.burst >= size);
  value->bucket_size = config.burst - size;
  value->bucket_time = time;

  map_put(state->subnet_indexers[i_subnet], key, index);

  vector_return(state->subnets[i_subnet], index, key);
  vector_return(state->subnet_buckets[i_subnet], index, value);

  return true;
}

void update_buckets(uint32_t src, uint16_t size, vigor_time_t time) {
  int index = -1;
  uint32_t mask = 0;

  bool captured_hh = false;
  uint32_t hh = 0;
  uint8_t hh_subnet_sz = 0;

  uint32_t subnets_mask = config.subnets_mask;

  for (int subnet = 0, subnet_i = -1; subnet < 32;
       subnet++, subnets_mask >>= 1) {
    mask = (mask >> 1) | (1 << 31);

    if (!(subnets_mask & 1)) {
      continue;
    }

    subnet_i++;
    uint32_t masked_src = src & SWAP_ENDIANNESS_32_BIT(mask);
    int present =
        map_get(state->subnet_indexers[subnet_i], &masked_src, &index);

    if (!present) {
      // NF_DEBUG("  [psz:%02d] src    %u.%u.%u.%u", (int)i +
      // config.min_subnet,
      //          (src >> 0) & 0xff, (src >> 8) & 0xff, (src >> 16) & 0xff,
      //          (src >> 24) & 0xff);
      // NF_DEBUG("  [psz:%02d] mask   %u.%u.%u.%u", (int)i +
      // config.min_subnet,
      //          (rte_bswap32(mask) >> 0) & 0xff, (rte_bswap32(mask) >> 8)
      //          & 0xff, (rte_bswap32(mask) >> 16) & 0xff,
      //          (rte_bswap32(mask) >> 24) & 0xff);
      // NF_DEBUG("  New subnet %u.%u.%u.%u/%d", (masked_src >> 0) & 0xff,
      //          (masked_src >> 8) & 0xff, (masked_src >> 16) & 0xff,
      //          (masked_src >> 24) & 0xff, (int)i + config.min_subnet);

      bool allocated = allocate(masked_src, subnet_i, size, time);

      // Not much we can do...
      if (!allocated) {
        return;
      }

      continue;
    }

    dchain_rejuvenate_index(state->allocators[subnet_i], index, time);

    struct DynamicValue *value = NULL;
    vector_borrow(state->subnet_buckets[subnet_i], index, (void **)&value);

    assert(0 <= time);
    uint64_t time_u = (uint64_t)time;
    assert(sizeof(vigor_time_t) == sizeof(int64_t));
    assert(value->bucket_time >= 0);
    assert(value->bucket_time <= time_u);
    uint64_t time_diff = time_u - value->bucket_time;

    if (time_diff < (config.burst * VIGOR_TIME_SECONDS_MULTIPLIER) /
                        state->threshold_rate) {
      uint64_t added_tokens =
          (time_diff * state->threshold_rate) / VIGOR_TIME_SECONDS_MULTIPLIER;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtautological-compare"
      vigor_note(0 <= time_diff * state->threshold_rate /
                          VIGOR_TIME_SECONDS_MULTIPLIER);
#pragma GCC diagnostic pop
      assert(value->bucket_size <= config.burst);
      value->bucket_size += added_tokens;
      if (value->bucket_size > config.burst) {
        value->bucket_size = config.burst;
      }
    } else {
      value->bucket_size = config.burst;
    }

    value->bucket_time = time_u;

    if (value->bucket_size > size) {
      value->bucket_size -= size;
    } else {
      captured_hh = true;
      hh = masked_src;
      hh_subnet_sz = subnet + 1;
    }

    vector_return(state->subnet_buckets[subnet_i], index, value);
  }

  if (captured_hh) {
    NF_DEBUG("HH detected: %0u.%u.%u.%u => %u.%u.%u.%u/%d", (src >> 0) & 0xff,
             (src >> 8) & 0xff, (src >> 16) & 0xff, (src >> 24) & 0xff,
             (hh >> 0) & 0xff, (hh >> 8) & 0xff, (hh >> 16) & 0xff,
             (hh >> 24) & 0xff, hh_subnet_sz);
  }
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);

  struct rte_ipv4_hdr *rte_ipv4_header =
      nf_then_get_rte_ipv4_header(rte_ether_header, buffer);
  if (rte_ipv4_header == NULL) {
    return device;
  }

  expire_entries(now);

  if (device == config.lan_device) {
    // Simply forward outgoing packets.
    NF_DEBUG("Outgoing packet. Not checking for heavy hitters.");
    return config.wan_device;
  } else if (device == config.wan_device) {
    update_buckets(rte_ipv4_header->src_addr, packet_length, now);

    // And just forward to LAN, we analyze without policing.
    return config.lan_device;
  } else {
    // Drop any other packets.
    NF_DEBUG("Unknown port. Dropping.");
    return device;
  }
}
