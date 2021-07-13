#include "nat_config.h"
#include "nf.h"
#include "nf-util.h"
#include "../nf-log.h"

struct nf_config config;

bool nf_init(void) { return true; }

int nf_process(uint16_t device, uint8_t *buffer, uint16_t packet_length,
               vigor_time_t now) {

  uint16_t dst_device;
  if (device == config.wan_device) {
    dst_device = config.lan_main_device;
  } else {
    dst_device = config.wan_device;
  }

  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);
  uint8_t *ip_options;
  struct rte_ipv4_hdr *rte_ipv4_header =
      nf_then_get_rte_ipv4_header(rte_ether_header, buffer, &ip_options);
  if (rte_ipv4_header == NULL) {
    return dst_device;
  }

  // struct tcpudp_hdr *tcpudp_header =
  //     nf_then_get_tcpudp_header(rte_ipv4_header, buffer);
  // if (tcpudp_header == NULL) {
  //   return device;
  // }

  NF_INFO("\n=========================================================");
  NF_INFO("---------------------------------------------------------");
  NF_INFO("Src:         %0x:%0x:%0x:%0x:%0x:%0x",
          rte_ether_header->s_addr.addr_bytes[0],
          rte_ether_header->s_addr.addr_bytes[1],
          rte_ether_header->s_addr.addr_bytes[2],
          rte_ether_header->s_addr.addr_bytes[3],
          rte_ether_header->s_addr.addr_bytes[4],
          rte_ether_header->s_addr.addr_bytes[5]);
  NF_INFO("Dst:         %0x:%0x:%0x:%0x:%0x:%0x",
          rte_ether_header->d_addr.addr_bytes[0],
          rte_ether_header->d_addr.addr_bytes[1],
          rte_ether_header->d_addr.addr_bytes[2],
          rte_ether_header->d_addr.addr_bytes[3],
          rte_ether_header->d_addr.addr_bytes[4],
          rte_ether_header->d_addr.addr_bytes[5]);
  NF_INFO("EtherType:   %x", rte_ether_header->ether_type);
  NF_INFO("---------------------------------------------------------");
  NF_INFO("Version:     %x", (rte_ipv4_header->version_ihl >> 8) & 0xff);
  NF_INFO("IHL:         %" PRIu8, rte_ipv4_header->version_ihl & 0xff);
  NF_INFO("ToS:         0x%x", rte_ipv4_header->type_of_service);
  NF_INFO("Length:      %" PRIu16, rte_ipv4_header->total_length);
  NF_INFO("ID:          %" PRIu16, rte_ipv4_header->packet_id);
  NF_INFO("Frag offset: %" PRIu16, rte_ipv4_header->fragment_offset);
  NF_INFO("TTL:         %" PRIu8, rte_ipv4_header->time_to_live);
  NF_INFO("Protocol:    0x%x", rte_ipv4_header->next_proto_id);
  NF_INFO("Checksum:    0x%x", rte_ipv4_header->hdr_checksum);
  NF_INFO("Src:         %u:%u:%u:%u", (rte_ipv4_header->src_addr >> 0) & 0xff,
          (rte_ipv4_header->src_addr >> 8) & 0xff,
          (rte_ipv4_header->src_addr >> 16) & 0xff,
          (rte_ipv4_header->src_addr >> 24) & 0xff);
  NF_INFO("Dst:         %u:%u:%u:%u", (rte_ipv4_header->dst_addr >> 0) & 0xff,
          (rte_ipv4_header->dst_addr >> 8) & 0xff,
          (rte_ipv4_header->dst_addr >> 16) & 0xff,
          (rte_ipv4_header->dst_addr >> 24) & 0xff);
  NF_INFO("---------------------------------------------------------");
  NF_INFO("=========================================================");

  return dst_device;
}
