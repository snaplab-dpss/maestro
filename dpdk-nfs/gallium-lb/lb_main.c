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

bool backend_from_flow(struct Flow *flow, uint32_t *new_dst_addr,
                       vigor_time_t now) {
  if (!match_backend(state, flow, new_dst_addr, now)) {
    NF_DEBUG("Allocating new flow...");
    if (!allocate_flow(state, flow, new_dst_addr, now)) {
      NF_DEBUG("Flow table is full.");
      return false;
    }
  }

  return true;
}

bool process_udp(struct rte_ipv4_hdr *ipv4_header,
                 struct rte_udp_hdr *udp_header, vigor_time_t now,
                 uint32_t *new_dst_addr) {
  struct Flow flow = { .src_addr = ipv4_header->src_addr,
                       .dst_addr = ipv4_header->dst_addr,
                       .src_port = udp_header->src_port,
                       .dst_port = udp_header->dst_port,
                       .protocol = ipv4_header->next_proto_id };

  if (!backend_from_flow(&flow, new_dst_addr, now)) {
    NF_DEBUG("Dropping.");
    return false;
  }

  NF_DEBUG("UDP src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u => dst=%u.%u.%u.%u",
           (flow.src_addr >> 0) & 0xff, (flow.src_addr >> 8) & 0xff,
           (flow.src_addr >> 16) & 0xff, (flow.src_addr >> 24) & 0xff,
           rte_be_to_cpu_16(flow.src_port), (flow.dst_addr >> 0) & 0xff,
           (flow.dst_addr >> 8) & 0xff, (flow.dst_addr >> 16) & 0xff,
           (flow.dst_addr >> 24) & 0xff, rte_be_to_cpu_16(flow.dst_port),
           (*new_dst_addr >> 0) & 0xff, (*new_dst_addr >> 8) & 0xff,
           (*new_dst_addr >> 16) & 0xff, (*new_dst_addr >> 24) & 0xff);

  return true;
}

bool process_tcp(struct rte_ipv4_hdr *ipv4_header,
                 struct rte_tcp_hdr *tcp_header, vigor_time_t now,
                 uint32_t *new_dst_addr) {
  struct Flow flow = { .src_addr = ipv4_header->src_addr,
                       .dst_addr = ipv4_header->dst_addr,
                       .src_port = tcp_header->src_port,
                       .dst_port = tcp_header->dst_port,
                       .protocol = ipv4_header->next_proto_id };

  int expire = tcp_header->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG);

  if (expire) {
    NF_DEBUG("FIN or RST!");
    if (!match_backend_and_expire_flow(state, &flow, new_dst_addr)) {
      NF_DEBUG("Trying to close a non-existing connection. Dropping.");
      return false;
    }
  } else {
    if (!backend_from_flow(&flow, new_dst_addr, now)) {
      NF_DEBUG("Dropping.");
      return false;
    }
  }

  NF_DEBUG("TCP src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u => dst=%u.%u.%u.%u",
           (flow.src_addr >> 0) & 0xff, (flow.src_addr >> 8) & 0xff,
           (flow.src_addr >> 16) & 0xff, (flow.src_addr >> 24) & 0xff,
           rte_be_to_cpu_16(flow.src_port), (flow.dst_addr >> 0) & 0xff,
           (flow.dst_addr >> 8) & 0xff, (flow.dst_addr >> 16) & 0xff,
           (flow.dst_addr >> 24) & 0xff, rte_be_to_cpu_16(flow.dst_port),
           (*new_dst_addr >> 0) & 0xff, (*new_dst_addr >> 8) & 0xff,
           (*new_dst_addr >> 16) & 0xff, (*new_dst_addr >> 24) & 0xff);

  return true;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  expire_flows(state, now);

  if (device == config.lan_device) {
    return config.wan_device;
  }

  struct rte_ether_hdr *ether_header = nf_then_get_rte_ether_header(buffer);
  struct rte_ipv4_hdr *ipv4_header =
      nf_then_get_rte_ipv4_header(ether_header, buffer);

  if (ipv4_header == NULL) {
    return device;
  }

  struct tcpudp_hdr *tcpudp_hdr;
  uint32_t new_dst_addr;

  struct rte_tcp_hdr *tcp_header = nf_then_get_tcp_header(ipv4_header, buffer);

  if (tcp_header == NULL) {
    struct rte_udp_hdr *udp_header =
        nf_then_get_udp_header(ipv4_header, buffer);

    if (udp_header == NULL) {
      return device;
    }

    if (!process_udp(ipv4_header, udp_header, now, &new_dst_addr)) {
      return device;
    }

    ipv4_header->dst_addr = new_dst_addr;
    nf_set_rte_ipv4_udptcp_checksum(ipv4_header,
                                    (struct tcpudp_hdr *)udp_header, buffer);
  } else {
    if (!process_tcp(ipv4_header, tcp_header, now, &new_dst_addr)) {
      return device;
    }

    ipv4_header->dst_addr = new_dst_addr;
    nf_set_rte_ipv4_udptcp_checksum(ipv4_header,
                                    (struct tcpudp_hdr *)tcp_header, buffer);
  }

  return config.lan_device;
}
