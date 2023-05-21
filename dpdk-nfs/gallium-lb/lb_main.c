#include "cfg_parser.h"
#include "lb_config.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"
#include "state.h"
#include "lib/unverified/util.h"

struct nf_config config;
struct State *state;

bool nf_init() {
  state = alloc_state(config.capacity, config.max_backends);

  if (state == NULL) {
    return false;
  }

  fill_table_from_file(state, &config);

  return true;
}

bool allocate_flow(struct Flow *flow, int *backend_index) {
  int index;
  int num_flows;
  int num_backends;

  struct Counter *flows_counter = 0;
  struct Counter *backends_counter = 0;

  vector_borrow(state->flows_counter, 0, (void **)&flows_counter);
  vector_borrow(state->backends_counter, 0, (void **)&backends_counter);

  num_flows = flows_counter->value;
  num_backends = backends_counter->value;
  index = num_flows;

  if (num_flows >= config.capacity || num_backends == 0) {
    vector_return(state->flows_counter, 0, flows_counter);
    vector_return(state->backends_counter, 0, backends_counter);
    return false;
  }

  flows_counter->value++;

  vector_return(state->flows_counter, 0, flows_counter);
  vector_return(state->backends_counter, 0, backends_counter);

  unsigned hash = hash_obj((void *)flow, sizeof(struct Flow));
  *backend_index = hash % num_backends;

  struct Flow *key = 0;
  vector_borrow(state->flows, index, (void **)&key);
  memcpy((void *)key, (void *)flow, sizeof(struct Flow));
  map_put(state->table, key, *backend_index);
  vector_return(state->flows, index, key);

  return true;
}

bool match_backend(struct Flow *flow, uint32_t *new_dst_addr) {
  int index;
  int present = map_get(state->table, flow, &index);

  if (!present) {
    NF_DEBUG("Allocating new flow...");
    if (!allocate_flow(flow, &index)) {
      return false;
    }
  }

  struct Backend *backend;
  vector_borrow(state->backends, index, (void **)&backend);
  *new_dst_addr = backend->ip;
  vector_return(state->backends, index, backend);

  return true;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *ether_header = nf_then_get_rte_ether_header(buffer);
  struct rte_ipv4_hdr *ipv4_header =
      nf_then_get_rte_ipv4_header(ether_header, buffer);

  if (ipv4_header == NULL) {
    return device;
  }

  struct tcpudp_hdr *tcpudp_header =
      nf_then_get_tcpudp_header(ipv4_header, buffer);

  if (tcpudp_header == NULL) {
    return device;
  }

  if (device == config.lan_device) {
    return config.wan_device;
  }

  struct Flow flow = { .src_port = tcpudp_header->src_port,
                       .dst_port = tcpudp_header->dst_port,
                       .src_addr = ipv4_header->src_addr,
                       .dst_addr = ipv4_header->dst_addr,
                       .protocol = ipv4_header->next_proto_id };

  uint32_t new_dst_addr;
  bool found = match_backend(&flow, &new_dst_addr);

  if (!found) {
    NF_DEBUG("Flow table is full. Dropping.");
    return device;
  }

  ipv4_header->dst_addr = new_dst_addr;
  nf_set_rte_ipv4_udptcp_checksum(ipv4_header, tcpudp_header, buffer);

  NF_DEBUG("src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u => dst=%u.%u.%u.%u",
           (flow.src_addr >> 0) & 0xff, (flow.src_addr >> 8) & 0xff,
           (flow.src_addr >> 16) & 0xff, (flow.src_addr >> 24) & 0xff,
           rte_be_to_cpu_16(flow.src_port), (flow.dst_addr >> 0) & 0xff,
           (flow.dst_addr >> 8) & 0xff, (flow.dst_addr >> 16) & 0xff,
           (flow.dst_addr >> 24) & 0xff, rte_be_to_cpu_16(flow.dst_port),
           (ipv4_header->dst_addr >> 0) & 0xff,
           (ipv4_header->dst_addr >> 8) & 0xff,
           (ipv4_header->dst_addr >> 16) & 0xff,
           (ipv4_header->dst_addr >> 24) & 0xff);

  return config.lan_device;
}
