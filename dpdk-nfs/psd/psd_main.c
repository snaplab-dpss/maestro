#include <stdint.h>
#include <assert.h>

#include <rte_byteorder.h>

#include "lib/verified/expirator.h"
#include "lib/unverified/expirator.h"

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
  assert(time >= 0);  // we don't support the past
  assert(sizeof(vigor_time_t) <= sizeof(uint64_t));
  uint64_t time_u = (uint64_t)time;  // OK because of the two asserts
  uint64_t expiration_time_ns =
      ((uint64_t)config.expiration_time) * 1000;  // us to ns
  vigor_time_t last_time = time_u - expiration_time_ns;
  expire_items_single_map(state->allocator, state->srcs_key, state->srcs,
                          last_time);
}

int allocate(uint32_t src, uint16_t target_port, vigor_time_t time) {
  int index = -1;
  int port_index = -1;

  int allocated = dchain_allocate_new_index(state->allocator, &index, time);

  if (!allocated) {
    // Nothing we can do...
    NF_DEBUG("No more space in the Port Scanner Detector source table");
    return false;
  }

  NF_DEBUG("Allocating %3u.%3u.%3u.%3u", (src >> 0) & 0xff, (src >> 8) & 0xff,
           (src >> 16) & 0xff, (src >> 24) & 0xff);

  uint32_t *src_key = NULL;
  uint32_t *counter = NULL;
  struct TouchedPort *touched_port = NULL;

  vector_borrow(state->srcs_key, index, (void **)&src_key);
  vector_borrow(state->touched_ports_counter, index, (void **)&counter);

  // Cleanup previous state first.
  expire_items_single_map_iteratively(state->ports_key, state->ports, index,
                                      *((int *)counter));

  // Now save the source and add the first port.
  port_index = 0;
  vector_borrow(state->ports_key, state->max_ports * index + port_index,
                (void **)&touched_port);

  *src_key = src;
  *counter = 1;
  touched_port->src = src;
  touched_port->port = target_port;

  map_put(state->srcs, src_key, index);
  map_put(state->ports, touched_port, port_index);

  vector_return(state->srcs_key, index, src_key);
  vector_return(state->touched_ports_counter, index, counter);
  vector_return(state->ports_key, state->max_ports * index + port_index,
                touched_port);

  return true;
}

// Return true if a port scanning is detected.
int detect_port_scanning(uint32_t src, uint16_t target_port,
                         vigor_time_t time) {
  int index = -1;
  int port_index = -1;
  int present = map_get(state->srcs, &src, &index);

  if (!present) {
    NF_DEBUG("Allocating %3u.%3u.%3u.%3u", (src >> 0) & 0xff, (src >> 8) & 0xff,
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

  uint32_t *counter = NULL;
  vector_borrow(state->touched_ports_counter, index, (void **)&counter);

  struct TouchedPort touched_port = {.src = src, .port = target_port};
  present = map_get(state->ports, &touched_port, &port_index);

  if (!present && *counter >= state->max_ports) {
    NF_DEBUG("Dropping   %3u.%3u.%3u.%3u", (src >> 0) & 0xff, (src >> 8) & 0xff,
             (src >> 16) & 0xff, (src >> 24) & 0xff);
    vector_return(state->touched_ports_counter, index, counter);
    return true;
  }

  if (!present) {
    struct TouchedPort *new_touched_port = NULL;
    port_index = *((int *)counter) - 1;

    vector_borrow(state->ports_key, state->max_ports * index + (port_index + 1),
                  (void **)&new_touched_port);

    (*counter)++;
    new_touched_port->src = src;
    new_touched_port->port = target_port;

    map_put(state->ports, new_touched_port, port_index + 1);

    vector_return(state->ports_key, state->max_ports * index + (port_index + 1),
                  new_touched_port);
  }

  vector_return(state->touched_ports_counter, index, counter);

  return false;
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
    NF_DEBUG("Outgoing packet. Not checking for port scanning attempts.");
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
