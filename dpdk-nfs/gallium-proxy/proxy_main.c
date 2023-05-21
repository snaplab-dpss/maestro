#include "cfg_parser.h"
#include "nf-log.h"
#include "nf-util.h"
#include "nf.h"
#include "proxy_config.h"
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

int match_backend(uint16_t dst_port, uint32_t *new_dst_ip,
                  uint16_t *new_dst_port) {
  struct Entry entry = { .port = dst_port };
  int index;
  int present = map_get(state->table, &entry, &index);

  if (!present) {
    return 0;
  }

  struct Backend *backend;
  vector_borrow(state->values, index, (void **)&backend);

  *new_dst_ip = backend->ip;
  *new_dst_port = backend->port;

  vector_return(state->values, index, backend);

  return 1;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *ether_header = nf_then_get_rte_ether_header(buffer);
  struct rte_ipv4_hdr *ipv4_header =
      nf_then_get_rte_ipv4_header(ether_header, buffer);

  if (ipv4_header == NULL) {
    NF_DEBUG("Not IPv4, dropping");
    return device;
  }

  struct tcpudp_hdr *tcpudp_header =
      nf_then_get_tcpudp_header(ipv4_header, buffer);

  if (tcpudp_header == NULL) {
    NF_DEBUG("Not TCP/UDP, dropping");
    return device;
  }

  if (device == config.lan_device) {
    return config.wan_device;
  }

  uint16_t dst_port = tcpudp_header->dst_port;
  uint32_t new_dst_addr;
  uint16_t new_dst_port;

  int found = match_backend(dst_port, &new_dst_addr, &new_dst_port);

  if (!found) {
    NF_DEBUG("Backend not found for this destination port (%d). Dropping.",
             rte_be_to_cpu_16(dst_port));
    return device;
  }

  ipv4_header->dst_addr = new_dst_addr;
  tcpudp_header->dst_port = new_dst_port;

  nf_set_rte_ipv4_udptcp_checksum(ipv4_header, tcpudp_header, buffer);

  NF_DEBUG(
      "[%u.%u.%u.%u:%u] %u => %u.%u.%u.%u:%u",
      (ipv4_header->src_addr >> 0) & 0xff, (ipv4_header->src_addr >> 8) & 0xff,
      (ipv4_header->src_addr >> 16) & 0xff,
      (ipv4_header->src_addr >> 24) & 0xff,
      rte_be_to_cpu_16(tcpudp_header->src_port), rte_be_to_cpu_16(dst_port),
      (ipv4_header->dst_addr >> 0) & 0xff, (ipv4_header->dst_addr >> 8) & 0xff,
      (ipv4_header->dst_addr >> 16) & 0xff,
      (ipv4_header->dst_addr >> 24) & 0xff,
      rte_be_to_cpu_16(tcpudp_header->dst_port));

  return config.lan_device;
}
