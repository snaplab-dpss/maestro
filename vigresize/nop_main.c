#include "nat_config.h"
#include "nf.h"
#include "nf-util.h"
#include "../nf-log.h"

struct nf_config config;

bool nf_init(void) { return true; }

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

  NF_INFO("Received a packet!");

  uint16_t dst_device;
  if (device == config.wan_device) {
    dst_device = config.lan_main_device;
  } else {
    dst_device = config.wan_device;
  }

  // =========================================================
  // Example 1: shorten IP options
  // if (!ip_options) {
  //   return device;
  // }

  // nf_return_chunk(buffer); // return TCP/UDP
  // nf_shrink_chunk(buffer, 2, mbuf);

  // rte_ether_header = (struct rte_ether_hdr *)nf_get_borrowed_chunk(0);
  // rte_ipv4_header = (struct rte_ipv4_hdr *)nf_get_borrowed_chunk(1);

  // ip_options = (uint8_t *)nf_get_borrowed_chunk(2);
  // =========================================================

  // =========================================================
  // Example 2: remove ip options
  // nf_return_chunk(buffer); // return TCP/UDP
  // nf_shrink_chunk(buffer, 0, mbuf);
  // =========================================================

  // =========================================================
  // Example 3: add new header after ip header (+ options)
  // nf_return_chunk(buffer); // return TCP/UDP
  //
  // size_t new_hdr_length = 8;
  // uint8_t* new_hdr = (uint8_t*) nf_insert_new_chunk(buffer, new_hdr_length,
  // mbuf);
  //
  // rte_ether_header = (struct rte_ether_hdr *) nf_get_borrowed_chunk(0);
  // rte_ipv4_header = (struct rte_ipv4_hdr *) nf_get_borrowed_chunk(1);
  //
  // if (ip_options) {
  //   ip_options = (uint8_t*) nf_get_borrowed_chunk(2);
  // }
  //
  // new_hdr[0] = 0xCA;
  // new_hdr[1] = 0xFE;
  // new_hdr[2] = 0xBA;
  // new_hdr[3] = 0xBE;
  // new_hdr[4] = 0xDE;
  // new_hdr[5] = 0xAD;
  // new_hdr[6] = 0xBE;
  // new_hdr[7] = 0xEF;
  // =========================================================

  // =========================================================
  // Example 4: add new header after ethernet header
  nf_return_chunk(buffer);  // return TCP/UDP
  if (ip_options) {
    nf_return_chunk(buffer);  // return IP options
  }
  nf_return_chunk(buffer);  // return IP

  size_t new_hdr_length = 8;
  uint8_t *new_hdr =
      (uint8_t *)nf_insert_new_chunk(buffer, new_hdr_length, mbuf);

  rte_ether_header = (struct rte_ether_hdr *)nf_get_borrowed_chunk(0);

  new_hdr[0] = 0xCA;
  new_hdr[1] = 0xFE;
  new_hdr[2] = 0xBA;
  new_hdr[3] = 0xBE;
  new_hdr[4] = 0xDE;
  new_hdr[5] = 0xAD;
  new_hdr[6] = 0xBE;
  new_hdr[7] = 0xEF;
  // =========================================================

  return dst_device;
}
