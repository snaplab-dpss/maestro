#include <stdint.h>
#include <assert.h>

#include <rte_byteorder.h>

#include "libvig/verified/expirator.h"
#include "libvig/unverified/expirator.h"

#include "nf.h"
#include "nf-log.h"
#include "nf-util.h"

#include "cl_config.h"
#include "cl_state.h"

struct nf_config config;
struct State *state;

bool nf_init(void) {
  uint32_t max_flows = config.max_flows;
  uint32_t sketch_capacity = config.sketch_capacity;
  uint16_t max_clients = config.max_clients;
  uint32_t dev_count = rte_eth_dev_count_avail();

  state = alloc_state(max_flows, sketch_capacity, max_clients, dev_count);

  return state != NULL;
}

void expire_entries(vigor_time_t time) {
  assert(time >= 0); // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time; // OK because of the two asserts
  uint64_t flow_expiration_time_ns =
      ((uint64_t)config.flow_expiration_time) * 1000; // us to ns
  uint64_t client_expiration_time_ns =
      ((uint64_t)config.client_expiration_time) * 1000; // us to ns
  vigor_time_t flow_last_time = time_u - flow_expiration_time_ns;
  vigor_time_t client_last_time = time_u - client_expiration_time_ns;
  expire_items_single_map(state->flow_allocator, state->flows_keys,
                          state->flows, flow_last_time);
  for (int i = 0; i < SKETCH_HASHES; i++) {
    expire_items_single_map_offseted(
        state->client_allocator[i], state->clients_keys, state->clients,
        client_last_time, i * state->sketch_capacity);
  }
}

int allocate_flow(struct flow *flow, vigor_time_t time) {
  int flow_index = -1;

  int allocated =
      dchain_allocate_new_index(state->flow_allocator, &flow_index, time);

  if (!allocated) {
    // Nothing we can do...
    NF_DEBUG("No more space in the flow table");
    return false;
  }

  NF_DEBUG("Allocating %u.%u.%u.%u:%u => %u.%u.%u.%u:%u",
           (flow->src_ip >> 0) & 0xff, (flow->src_ip >> 8) & 0xff,
           (flow->src_ip >> 16) & 0xff, (flow->src_ip >> 24) & 0xff,
           flow->src_port, (flow->dst_ip >> 0) & 0xff,
           (flow->dst_ip >> 8) & 0xff, (flow->dst_ip >> 16) & 0xff,
           (flow->dst_ip >> 24) & 0xff, flow->dst_port);

  struct flow *new_flow = NULL;
  vector_borrow(state->flows_keys, flow_index, (void **)&new_flow);
  memcpy((void *)new_flow, (void *)flow, sizeof(struct flow));
  map_put(state->flows, new_flow, flow_index);
  vector_return(state->flows_keys, flow_index, new_flow);

  return true;
}

int touch_bucket(int sketch_iteration, unsigned sketch_hash, vigor_time_t now) {
  assert(sketch_iteration >= 0 && sketch_iteration < SKETCH_HASHES);

  int bucket_index = -1;
  int present = map_get(state->clients, &sketch_hash, &bucket_index);

  if (!present) {
    int allocated_client = dchain_allocate_new_index(
        state->client_allocator[sketch_iteration], &bucket_index, now);

    if (!allocated_client) {
      // Sketch size limit reached.
      return false;
    }

    int offseted = bucket_index + state->sketch_capacity * sketch_iteration;

    uint32_t *saved_hash = NULL;
    uint32_t *saved_bucket = NULL;

    vector_borrow(state->clients_keys, offseted, (void **)&saved_hash);
    vector_borrow(state->clients_buckets, offseted, (void **)&saved_bucket);

    (*saved_hash) = sketch_hash;
    (*saved_bucket) = 0;
    map_put(state->clients, saved_hash, bucket_index);

    vector_return(state->clients_keys, offseted, saved_hash);
    vector_return(state->clients_buckets, offseted, saved_bucket);

    return true;
  } else {
    dchain_rejuvenate_index(state->client_allocator[sketch_iteration],
                            bucket_index, now);
    uint32_t *bucket;
    int offseted = bucket_index + state->sketch_capacity * sketch_iteration;
    vector_borrow(state->clients_buckets, offseted, (void **)&bucket);
    (*bucket)++;
    vector_return(state->clients_buckets, offseted, bucket);
    return true;
  }
}

// Return false if packet should be dropped
int limit_clients(struct flow *flow, vigor_time_t now) {
  int flow_index = -1;
  int present = map_get(state->flows, flow, &flow_index);

  struct hash_input hash_input = { .src_ip = flow->src_ip,
                                   .dst_ip = flow->dst_ip };

  unsigned hashes[SKETCH_HASHES];
  int bucket_indexes[SKETCH_HASHES];
  int hash_present[SKETCH_HASHES];
  int all_hashes_present = true;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    bucket_indexes[i] = -1;
    hash_present[i] = 0;
    hashes[i] =
        sketch_hash(&hash_input, SKETCH_SALTS[i], config.sketch_capacity);
  }

  if (!present) {
    int allocated_flow = allocate_flow(flow, now);

    if (!allocated_flow) {
      // Reached the maximum number of allowed flows.
      // Just forward and don't limit...
      return true;
    }

    for (int i = 0; i < SKETCH_HASHES; i++) {
      hash_present[i] = map_get(state->clients, &hashes[i], &bucket_indexes[i]);
      all_hashes_present &= hash_present[i];
    }

    if (all_hashes_present) {
      uint32_t *buckets[SKETCH_HASHES];
      uint32_t bucket_min = -1;

      for (int i = 0; i < SKETCH_HASHES; i++) {
        int offseted = bucket_indexes[i] + state->sketch_capacity * i;
        vector_borrow(state->clients_buckets, offseted, (void **)&buckets[i]);
        if (bucket_min == -1 || bucket_min > *buckets[i]) {
          bucket_min = *buckets[i];
        }
        vector_return(state->clients_buckets, offseted, buckets[i]);
      }

      if (bucket_min < state->max_clients) {
        for (int i = 0; i < SKETCH_HASHES; i++) {
          int offseted = bucket_indexes[i] + state->sketch_capacity * i;
          vector_borrow(state->clients_buckets, offseted, (void **)&buckets[i]);
          (*buckets[i])++;
          vector_return(state->clients_buckets, offseted, buckets[i]);
        }

        return true;
      } else {
        // Maximum number of clients reached. Drop!
        return false;
      }
    } else {
      for (int i = 0; i < SKETCH_HASHES; i++) {
        touch_bucket(i, hashes[i], now);
      }
      return true;
    }
  } else {
    dchain_rejuvenate_index(state->flow_allocator, flow_index, now);

    for (int i = 0; i < SKETCH_HASHES; i++) {
      present = map_get(state->clients, &hashes[i], &bucket_indexes[i]);
      dchain_rejuvenate_index(state->client_allocator[i], bucket_indexes[i],
                              now);
    }

    return true;
  }
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {

  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);

  uint8_t *ip_options;
  struct rte_ipv4_hdr *rte_ipv4_header =
      nf_then_get_rte_ipv4_header(rte_ether_header, buffer, &ip_options);
  if (rte_ipv4_header == NULL) {
    return device;
  }

  struct tcpudp_hdr *tcpudp_header =
      nf_then_get_tcpudp_header(rte_ipv4_header, buffer);
  if (tcpudp_header == NULL) {
    return device;
  }

  expire_entries(now);

  if (device == config.lan_device) {
    // Simply forward outgoing packets.
    NF_DEBUG("Outgoing packet. Not limiting clients.");
    return config.wan_device;
  } else if (device == config.wan_device) {
    struct flow flow = { .src_port = tcpudp_header->src_port,
                         .dst_port = tcpudp_header->dst_port,
                         .src_ip = rte_ipv4_header->src_addr,
                         .dst_ip = rte_ipv4_header->dst_addr,
                         .protocol = rte_ipv4_header->next_proto_id, };

    int fwd = limit_clients(&flow, now);

    if (fwd) {
      return config.lan_device;
    }

    // Drop packet.
    NF_DEBUG("Limiting   %u.%u.%u.%u:%u => %u.%u.%u.%u:%u",
             (flow.src_ip >> 0) & 0xff, (flow.src_ip >> 8) & 0xff,
             (flow.src_ip >> 16) & 0xff, (flow.src_ip >> 24) & 0xff,
             flow.src_port, (flow.dst_ip >> 0) & 0xff,
             (flow.dst_ip >> 8) & 0xff, (flow.dst_ip >> 16) & 0xff,
             (flow.dst_ip >> 24) & 0xff, flow.dst_port);
    return device;
  } else {
    // Drop any other packets.
    NF_DEBUG("Unknown port. Dropping.");
    return device;
  }

  return device;
}
