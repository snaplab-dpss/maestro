#include "cfg_parser.h"
#include "lb_config.h"
#include "lb_manager.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"
#include "state.h"

struct nf_config config;
struct State *state;

bool nf_init() {
  state = alloc_state(config.max_flows, config.expiration_time,
                      config.num_backends);

  if (state == NULL) {
    return false;
  }

  fill_table_from_file(state, &config);

  return true;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  expire_flows(state, now);

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

  if (!match_backend(state, &flow, &new_dst_addr, now)) {
    NF_DEBUG("Allocating new flow...");
    if (!allocate_flow(state, &flow, &new_dst_addr, now)) {
      NF_DEBUG("Flow table is full. Dropping.");
      return device;
    }
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
