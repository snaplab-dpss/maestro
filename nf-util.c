#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <netinet/in.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "nf-util.h"
#include "nf-log.h"

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#endif

void *chunks_borrowed[MAX_N_CHUNKS];
size_t chunks_borrowed_num = 0;

void nf_log_pkt(struct rte_ether_hdr *rte_ether_header,
                struct rte_ipv4_hdr *rte_ipv4_header,
                struct tcpudp_hdr *tcpudp_header) {
  NF_INFO("###[ Ethernet ]###");
  NF_INFO("  dst  %02x:%02x:%02x:%02x:%02x:%02x",
          rte_ether_header->d_addr.addr_bytes[0],
          rte_ether_header->d_addr.addr_bytes[1],
          rte_ether_header->d_addr.addr_bytes[2],
          rte_ether_header->d_addr.addr_bytes[3],
          rte_ether_header->d_addr.addr_bytes[4],
          rte_ether_header->d_addr.addr_bytes[5]);
  NF_INFO("  src  %02x:%02x:%02x:%02x:%02x:%02x",
          rte_ether_header->s_addr.addr_bytes[0],
          rte_ether_header->s_addr.addr_bytes[1],
          rte_ether_header->s_addr.addr_bytes[2],
          rte_ether_header->s_addr.addr_bytes[3],
          rte_ether_header->s_addr.addr_bytes[4],
          rte_ether_header->s_addr.addr_bytes[5]);
  NF_INFO("  type 0x%x", rte_bswap16(rte_ether_header->ether_type));

  NF_INFO("###[ IP ]###");
  NF_INFO("  ihl     %u", (rte_ipv4_header->version_ihl & 0x0f));
  NF_INFO("  version %u", (rte_ipv4_header->version_ihl & 0xf0) >> 4);
  NF_INFO("  tos     %u", rte_ipv4_header->type_of_service);
  NF_INFO("  len     %u", rte_bswap16(rte_ipv4_header->total_length));
  NF_INFO("  id      %u", rte_bswap16(rte_ipv4_header->packet_id));
  NF_INFO("  off     %u", rte_bswap16(rte_ipv4_header->fragment_offset));
  NF_INFO("  ttl     %u", rte_ipv4_header->time_to_live);
  NF_INFO("  proto   %u", rte_ipv4_header->next_proto_id);
  NF_INFO("  chksum  0x%x", rte_bswap16(rte_ipv4_header->hdr_checksum));
  NF_INFO("  src     %u.%u.%u.%u", (rte_ipv4_header->src_addr >> 0) & 0xff,
          (rte_ipv4_header->src_addr >> 8) & 0xff,
          (rte_ipv4_header->src_addr >> 16) & 0xff,
          (rte_ipv4_header->src_addr >> 24) & 0xff);
  NF_INFO("  dst     %u.%u.%u.%u", (rte_ipv4_header->dst_addr >> 0) & 0xff,
          (rte_ipv4_header->dst_addr >> 8) & 0xff,
          (rte_ipv4_header->dst_addr >> 16) & 0xff,
          (rte_ipv4_header->dst_addr >> 24) & 0xff);

  NF_INFO("###[ UDP ]###");
  NF_INFO("  sport   %u", rte_bswap16(tcpudp_header->src_port));
  NF_INFO("  dport   %u", rte_bswap16(tcpudp_header->dst_port));
}

bool nf_has_rte_ipv4_header(struct rte_ether_hdr *header) {
  return header->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4);
}

bool nf_has_tcpudp_header(struct rte_ipv4_hdr *header) {
  // NOTE: Use non-short-circuiting version of OR, so that symbex doesn't fork
  //       since here we only care of it's UDP or TCP, not if it's a specific
  //       one
  return header->next_proto_id == IPPROTO_TCP |
         header->next_proto_id == IPPROTO_UDP;
}

#ifdef KLEE_VERIFICATION
void nf_set_rte_ipv4_udptcp_checksum(struct rte_ipv4_hdr *ip_header,
                                     struct tcpudp_hdr *l4_header,
                                     void *packet) {
  klee_trace_ret();
  klee_trace_param_u64((uint64_t)ip_header, "ip_header");
  klee_trace_param_u64((uint64_t)l4_header, "l4_header");
  klee_trace_param_u64((uint64_t)packet, "packet");
  // Make sure the packet pointer points to the TCPUDP continuation
  assert(packet_is_last_borrowed_chunk(packet, l4_header));
  ip_header->hdr_checksum = klee_int("checksum");
}
#else   // KLEE_VERIFICATION
void nf_set_rte_ipv4_udptcp_checksum(struct rte_ipv4_hdr *ip_header,
                                     struct tcpudp_hdr *l4_header,
                                     void *packet) {
  // Make sure the packet pointer points to the TCPUDP continuation
  // This check is exercised during verification, no need to repeat it.
  // void* payload = nf_borrow_next_chunk(packet,
  // rte_be_to_cpu_16(ip_header->total_length) - sizeof(struct tcpudp_hdr));
  // assert((char*)payload == ((char*)l4_header + sizeof(struct tcpudp_hdr)));

  ip_header->hdr_checksum = 0;  // Assumed by cksum calculation
  if (ip_header->next_proto_id == IPPROTO_TCP) {
    struct rte_tcp_hdr *tcp_header = (struct rte_tcp_hdr *)l4_header;
    tcp_header->cksum = 0;  // Assumed by cksum calculation
    tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header, tcp_header);
  } else if (ip_header->next_proto_id == IPPROTO_UDP) {
    struct rte_udp_hdr *udp_header = (struct rte_udp_hdr *)l4_header;
    udp_header->dgram_cksum = 0;  // Assumed by cksum calculation
    udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ip_header, udp_header);
  }
  ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);
}
#endif  // KLEE_VERIFICATION

uintmax_t nf_util_parse_int(const char *str, const char *name, int base,
                            char next) {
  char *temp;
  intmax_t result = strtoimax(str, &temp, base);

  // There's also a weird failure case with overflows, but let's not care
  if (temp == str || *temp != next) {
    rte_exit(EXIT_FAILURE, "Error while parsing '%s': %s\n", name, str);
  }

  return result;
}

char *nf_mac_to_str(struct rte_ether_addr *addr) {
  // format is xx:xx:xx:xx:xx:xx\0
  uint16_t buffer_size = 6 * 2 + 5 + 1;  // FIXME: why dynamic alloc here?
  char *buffer = (char *)calloc(buffer_size, sizeof(char));
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_mac_to_str!");
  }

  snprintf(buffer, buffer_size, "%02X:%02X:%02X:%02X:%02X:%02X",
           addr->addr_bytes[0], addr->addr_bytes[1], addr->addr_bytes[2],
           addr->addr_bytes[3], addr->addr_bytes[4], addr->addr_bytes[5]);

  return buffer;
}

char *nf_rte_ipv4_to_str(uint32_t addr) {
  // format is xxx.xxx.xxx.xxx\0
  uint16_t buffer_size = 4 * 3 + 3 + 1;
  char *buffer = (char *)calloc(
      buffer_size, sizeof(char));  // FIXME: why dynamic alloc here?
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_rte_ipv4_to_str!");
  }

  snprintf(buffer, buffer_size, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
           addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
           (addr >> 24) & 0xFF);
  return buffer;
}
