#include "cfg_parser.h"
#include "fw_config.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"
#include "state.h"

struct nf_config config;
struct State *state;

bool nf_init() {
  state = alloc_state(config.capacity);

  if (state == NULL) {
    return false;
  }

  fill_table_from_file(state, &config);

  return true;
}

bool is_flow_allowed(struct Flow *flow) {
  int index;
  return map_get(state->table, flow, &index);
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

  struct Flow flow = {
    .src_addr = ipv4_header->src_addr,
    .dst_addr = ipv4_header->dst_addr,
    .src_port = tcpudp_header->src_port,
    .dst_port = tcpudp_header->dst_port,
    .device = device,
    .proto = ipv4_header->next_proto_id,
  };

  bool allowed = is_flow_allowed(&flow);

  if (!allowed) {
    NF_DEBUG("Flow not allowed, dropped.");
    return device;
  }

  NF_DEBUG("Allow flow: [device=%u] %u.%u.%u.%u:%u => %u.%u.%u.%u:%u proto=%u",
           flow.device, (flow.src_addr >> 0) & 0xff,
           (flow.src_addr >> 8) & 0xff, (flow.src_addr >> 16) & 0xff,
           (flow.src_addr >> 24) & 0xff, rte_be_to_cpu_16(flow.src_port),
           (flow.dst_addr >> 0) & 0xff, (flow.dst_addr >> 8) & 0xff,
           (flow.dst_addr >> 16) & 0xff, (flow.dst_addr >> 24) & 0xff,
           rte_be_to_cpu_16(flow.dst_port), flow.proto);

  return device == config.lan_device ? config.wan_device : config.lan_device;
}
