#include <stdlib.h>

#include "nat_config.h"
#include "nat_flowmanager.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"

struct nf_config config;

struct State *state;

bool nf_init(void) {
  state = alloc_state(config.max_flows, config.external_addr);
  return state != NULL;
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

  NF_DEBUG("Forwarding an IPv4 packet on device %" PRIu16, device);
  uint16_t dst_device;

  if (device == config.wan_device) {
    NF_DEBUG("WAN packet");

    struct Flow internal_flow;
    if (external_get(state, tcpudp_header->dst_port, &internal_flow)) {
      NF_DEBUG("Found internal flow.");

      if (internal_flow.dst_addr != ipv4_header->src_addr ||
          internal_flow.dst_port != tcpudp_header->src_port ||
          internal_flow.protocol != ipv4_header->next_proto_id) {
        NF_DEBUG("Spoofing attempt, dropping.");
        return device;
      }

      ipv4_header->dst_addr = internal_flow.src_addr;
      tcpudp_header->dst_port = internal_flow.src_port;
      dst_device = config.lan_device;
    } else {
      NF_DEBUG("Unknown flow, dropping");
      return device;
    }
  } else {
    NF_DEBUG("LAN packet");

    struct Flow flow = { .src_port = tcpudp_header->src_port,
                         .dst_port = tcpudp_header->dst_port,
                         .src_addr = ipv4_header->src_addr,
                         .dst_addr = ipv4_header->dst_addr,
                         .protocol = ipv4_header->next_proto_id };

    uint16_t external_port;

    if (!internal_get(state, &flow, &external_port)) {
      NF_DEBUG("New flow");

      if (!allocate_flow(state, &flow, &external_port)) {
        NF_DEBUG("No space for the flow, dropping");
        return device;
      }
    }

    NF_DEBUG("Forwarding from ext port: %d", rte_be_to_cpu_16(external_port));

    ipv4_header->src_addr = config.external_addr;
    tcpudp_header->src_port = external_port;
    dst_device = config.wan_device;
  }

  nf_set_rte_ipv4_udptcp_checksum(ipv4_header, tcpudp_header, buffer);

  return dst_device;
}
