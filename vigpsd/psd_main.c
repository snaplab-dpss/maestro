#include <stdint.h>
#include <assert.h>

#include <rte_byteorder.h>

#include "libvig/verified/expirator.h"

#include "nf.h"
#include "nf-log.h"
#include "nf-util.h"

#include "psd_config.h"
#include "psd_state.h"

struct nf_config config;
struct State *state;

bool nf_init(void) {
  uint32_t capacity = config.capacity;
  uint16_t max_ports = config.max_ports;
  uint32_t dev_count = rte_eth_dev_count_avail();

  state = alloc_state(capacity, max_ports, dev_count);

  return state != NULL;
}

void expire_entries(vigor_time_t time) {
  assert(time >= 0); // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time; // OK because of the two asserts
  uint64_t expiration_time_ns = (uint64_t)config.expiration_time;
  vigor_time_t last_time = time_u - expiration_time_ns * 1000; // us to ns
  int expired = expire_items_single_map(state->allocator, state->srcs_key,
                                        state->srcs, last_time);
}

void update_scanned_ports(struct ScannedPorts *sp, uint16_t port) {
  int bucket_pos = BUCKET_POS(port);
  ports_bucket_t port_pos = PORT_POS(port);

  if (!PORT_FROM_BUCKETS(sp->buckets, port)) {
    ports_bucket_t mask = 1 << port_pos;
    sp->buckets[bucket_pos] |= mask;
    sp->total++;
  }
}

int allocate(uint32_t src, uint16_t target_port, vigor_time_t time) {
  int index = -1;

  int allocated = dchain_allocate_new_index(state->allocator, &index, time);

  if (!allocated) {
    // Nothing we can do...
    NF_DEBUG("No more space in the Port Scanner Detector source table");
    return false;
  }

  uint32_t *src_key;
  struct ScannedPorts *scanned_ports = NULL;

  vector_borrow(state->srcs_key, index, (void **)&src_key);
  vector_borrow(state->scanned_ports, index, (void **)&scanned_ports);

  *src_key = src;

  ScannedPorts_allocate((void *)scanned_ports);
  update_scanned_ports(scanned_ports, target_port);

  map_put(state->srcs, src_key, index);

  vector_return(state->scanned_ports, index, src_key);
  vector_return(state->scanned_ports, index, scanned_ports);

  return true;
}

// Return true if a port scanning is detected.
int detect_port_scanning(uint32_t src, uint16_t target_port,
                         vigor_time_t time) {
  int detected = 0;
  int index = -1;
  int present = map_get(state->srcs, &src, &index);

  if (!present) {
    NF_DEBUG("Allocating %u.%u.%u.%u", (src >> 0) & 0xff, (src >> 8) & 0xff,
             (src >> 16) & 0xff, (src >> 24) & 0xff);

    bool allocated = allocate(src, target_port, time);

    if (!allocated) {
      // Nothing we can do, the table is full...
      NF_DEBUG("No more space");
      return false;
    }

    return false;
  }

  dchain_rejuvenate_index(state->allocator, index, time);

  struct ScannedPorts *scanned_ports = NULL;

  vector_borrow(state->scanned_ports, index, (void **)&scanned_ports);
  update_scanned_ports(scanned_ports, target_port);
  detected = scanned_ports->total > config.max_ports;
  vector_return(state->scanned_ports, index, scanned_ports);

  if (detected) {
    NF_DEBUG("Dropping port scanner %u.%u.%u.%u", (src >> 0) & 0xff,
             (src >> 8) & 0xff, (src >> 16) & 0xff, (src >> 24) & 0xff);
  }

  return detected;
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
    NF_DEBUG("Outgoing packet. Not checking for heavy hitters.");
    return config.wan_device;
  } else if (device == config.wan_device) {
    int detected = detect_port_scanning(rte_ipv4_header->src_addr,
                                        tcpudp_header->dst_port, now);

    if (detected) {
      // Drop packet.
      return device;
    }

    // OK to forward.
    return config.lan_device;
  } else {
    // Drop any other packets.
    NF_DEBUG("Unknown port. Dropping.");
    return device;
  }

  return device;
}
