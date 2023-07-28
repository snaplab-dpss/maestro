#include <stdint.h>
#include <assert.h>

#include <rte_byteorder.h>

#include "lib/verified/expirator.h"
#include "lib/unverified/expirator.h"

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
  assert(time >= 0);  // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time;  // OK because of the two asserts
  uint64_t flow_expiration_time_ns =
      ((uint64_t)config.flow_expiration_time) * 1000;  // us to ns
  uint64_t client_expiration_time_ns =
      ((uint64_t)config.client_expiration_time) * 1000;  // us to ns
  vigor_time_t flow_last_time = time_u - flow_expiration_time_ns;
  vigor_time_t client_last_time = time_u - client_expiration_time_ns;
  expire_items_single_map(state->flow_allocator, state->flows_keys,
                          state->flows, flow_last_time);
  sketch_expire(state->sketch, client_last_time);
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

// Return false if packet should be dropped
int limit_clients(struct flow *flow, vigor_time_t now) {
  int flow_index = -1;
  int present = map_get(state->flows, flow, &flow_index);

  struct client client = {.src_ip = flow->src_ip, .dst_ip = flow->dst_ip};

  sketch_compute_hashes(state->sketch, &client);

  if (present) {
    dchain_rejuvenate_index(state->flow_allocator, flow_index, now);
    sketch_refresh(state->sketch, now);
    return true;
  }

  int allocated_flow = allocate_flow(flow, now);

  if (!allocated_flow) {
    // Reached the maximum number of allowed flows.
    // Just forward and don't limit...
    return true;
  }

  int overflow = sketch_fetch(state->sketch);

  if (overflow) {
    return false;
  }

  sketch_touch_buckets(state->sketch, now);

  return true;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);

  struct rte_ipv4_hdr *rte_ipv4_header =
      nf_then_get_rte_ipv4_header(rte_ether_header, buffer);
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
    struct flow flow = {
        .src_port = tcpudp_header->src_port,
        .dst_port = tcpudp_header->dst_port,
        .src_ip = rte_ipv4_header->src_addr,
        .dst_ip = rte_ipv4_header->dst_addr,
        .protocol = rte_ipv4_header->next_proto_id,
    };

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
