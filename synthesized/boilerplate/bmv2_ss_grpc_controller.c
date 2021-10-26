#include <linux/limits.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>

#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/tcpudp_hdr.h"
#include "libvig/verified/vigor-time.h"
#include "libvig/verified/ether.h"

#include "libvig/verified/double-chain.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/map.h"
#include "libvig/verified/expirator.h"
#include "libvig/verified/cht.h"

/**********************************************
 *
 *                  PACKET-IO
 *
 **********************************************/

size_t global_total_length;
size_t global_read_length = 0;

void packet_state_total_length(void *p, uint32_t *len)
/*@ requires packetp(p, ?unread, nil) &*&
 *len |-> length(unread); @*/
/*@ ensures packetp(p, unread, nil) &*&
 *len |-> length(unread); @*/
{
  //@ open packetp(p, unread, nil);
  // IGNORE(p);
  global_total_length = *len;
  //@ close packetp(p, unread, nil);
}

/*@
  lemma void borrowed_len_nonneg(list<pair<int8_t*, int> > missing_chunks,
                                 int8_t* start, int8_t* beginning)
  requires true == missing_chunks(missing_chunks, start, beginning);
  ensures 0 <= borrowed_len(missing_chunks);
  {
    switch(missing_chunks) {
      case nil:
      case cons(h,t):
        switch(h) { case pair(beg, span):
          borrowed_len_nonneg(t, start, beg);
        }
    }
  }
@*/

// The main IO primitive.
void packet_borrow_next_chunk(void *p, size_t length, void **chunk)
/*@ requires packetp(p, ?unread, ?mc) &*&
             length <= length(unread) &*&
             0 < length &*& length < INT_MAX &*&
             length + borrowed_len(mc) < INT_MAX &*&
             *chunk |-> _; @*/
/*@ ensures *chunk |-> ?ptr &*&
            ptr != 0 &*&
            packetp(p, drop(length, unread), cons(pair(ptr, length), mc)) &*&
            chars(ptr, length, take(length, unread)); @*/
{
  //@ open packetp(p, unread, mc);
  //@ borrowed_len_nonneg(mc, p, p + borrowed_len(mc));
  //@ assert 0 <= global_read_length;
  //@ assert p > 0;
  //@ assert p + global_read_length > 0;
  // TODO: support mbuf chains.
  *chunk = (char *)p + global_read_length;
  //@ chars_split(*chunk, length);
  global_read_length += length;
  //@ assert *chunk |-> ?ptr;
  //@ close packetp(p, drop(length, unread), cons(pair(ptr, length), mc));
}

void packet_return_chunk(void *p, void *chunk)
/*@ requires packetp(p, ?unread, cons(pair(chunk, ?len), ?mc)) &*&
             chars(chunk, len, ?chnk); @*/
/*@ ensures packetp(p, append(chnk, unread), mc); @*/
{
  //@ open packetp(p, unread, cons(pair(chunk, len), mc));
  global_read_length = (uint32_t)((int8_t *)chunk - (int8_t *)p);
  //@ close packetp(p, append(chnk, unread), mc);
}

size_t packet_get_chunk_length(void *p, void *chunk) {
  return (uint32_t)(((char *)p + global_read_length) - (char *)chunk);
}

void packet_shrink_chunk(void **p, size_t length, void **chunks,
                         size_t num_chunks, struct rte_mbuf *mbuf) {
  uint8_t *data = (uint8_t *)(*p);

  void *last_chunk = chunks[num_chunks - 1];
  size_t last_chunk_length = packet_get_chunk_length(data, last_chunk);
  uint8_t *last_chunk_limit = last_chunk + last_chunk_length;

  assert(length <= last_chunk_length);
  size_t offset = last_chunk_length - length;

  if (offset == 0) {
    return;
  }

  uint8_t *current = last_chunk_limit - 1;

  while (current >= data + offset) {
    rte_memcpy(current, current - offset, 1);
    current--;
  }

  data = (uint8_t *)rte_pktmbuf_adj(mbuf, offset);
  assert(data);

  global_read_length -= offset;
  global_total_length -= offset;

  for (int i = 0; i < num_chunks; i++) {
    chunks[i] += offset;
  }

  (*p) = data;
}

void packet_insert_new_chunk(void **p, size_t length, void **chunks,
                             size_t *num_chunks, struct rte_mbuf *mbuf) {
  uint8_t *data = (uint8_t *)(*p);
  uint8_t *last_chunk_limit = data + global_read_length;

  data = (uint8_t *)rte_pktmbuf_prepend(mbuf, length);
  assert(data);

  uint8_t *current = data;

  while (current + length < last_chunk_limit) {
    rte_memcpy(current, current + length, 1);
    current++;
  }

  for (int i = 0; i < (*num_chunks); i++) {
    chunks[i] -= length;
  }

  assert(chunks[0] == data);

  (*num_chunks)++;
  (*p) = data;

  chunks[(*num_chunks) - 1] = data + global_read_length;

  global_read_length += length;
  global_total_length += length;
}

uint32_t packet_get_unread_length(void *p) {
  return global_total_length - global_read_length;
}

/**********************************************
 *
 *              SYNAPSE-RUNTIME
 *
 **********************************************/

#include "synthesized/synapse-runtime/util.h"
#include "synapse/runtime/wrapper/connector.hpp"

/**********************************************
 *
 *                  NF-UTIL
 *
 **********************************************/

// rte_ether
struct rte_ether_addr;
struct rte_ether_hdr;

#define IP_MIN_SIZE_WORDS 5
#define MAX_N_CHUNKS 100
#define WORD_SIZE 4

#define CHUNK_LAYOUT_IMPL(pkt, len, fields, n_fields, nests, n_nests, tag)

#define CHUNK_LAYOUT_N(pkt, str_name, fields, nests)                           \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,                      \
                    sizeof(fields) / sizeof(fields[0]), nests,                 \
                    sizeof(nests) / sizeof(nests[0]), #str_name);

#define CHUNK_LAYOUT(pkt, str_name, fields)                                    \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,                      \
                    sizeof(fields) / sizeof(fields[0]), NULL, 0, #str_name);

void *chunks_borrowed[MAX_N_CHUNKS];
size_t chunks_borrowed_num = 0;

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

void nf_set_rte_ipv4_udptcp_checksum(struct rte_ipv4_hdr *ip_header,
                                     struct tcpudp_hdr *l4_header,
                                     void *packet) {
  // Make sure the packet pointer points to the TCPUDP continuation
  // This check is exercised during verification, no need to repeat it.
  // void* payload = nf_borrow_next_chunk(packet,
  // rte_be_to_cpu_16(ip_header->total_length) - sizeof(struct tcpudp_hdr));
  // assert((char*)payload == ((char*)l4_header + sizeof(struct tcpudp_hdr)));

  ip_header->hdr_checksum = 0; // Assumed by cksum calculation
  if (ip_header->next_proto_id == IPPROTO_TCP) {
    struct rte_tcp_hdr *tcp_header = (struct rte_tcp_hdr *)l4_header;
    tcp_header->cksum = 0; // Assumed by cksum calculation
    tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header, tcp_header);
  } else if (ip_header->next_proto_id == IPPROTO_UDP) {
    struct rte_udp_hdr *udp_header = (struct rte_udp_hdr *)l4_header;
    udp_header->dgram_cksum = 0; // Assumed by cksum calculation
    udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ip_header, udp_header);
  }
  ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);
}

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
  uint16_t buffer_size = 6 * 2 + 5 + 1; // FIXME: why dynamic alloc here?
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
  char *buffer = (char *)calloc(buffer_size,
                                sizeof(char)); // FIXME: why dynamic alloc here?
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_rte_ipv4_to_str!");
  }

  snprintf(buffer, buffer_size, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
           addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
           (addr >> 24) & 0xFF);
  return buffer;
}

static inline void *nf_borrow_next_chunk(uint8_t **p, size_t length) {
  assert(chunks_borrowed_num < MAX_N_CHUNKS);
  void *chunk;
  packet_borrow_next_chunk(*p, length, &chunk);
  chunks_borrowed[chunks_borrowed_num] = chunk;
  chunks_borrowed_num++;
  return chunk;
}

static inline void *nf_shrink_chunk(uint8_t **p, size_t length,
                                    struct rte_mbuf *mbuf) {
  assert(chunks_borrowed_num < MAX_N_CHUNKS);
  assert(chunks_borrowed_num);
  packet_shrink_chunk((void **)p, length, chunks_borrowed, chunks_borrowed_num,
                      mbuf);
  return chunks_borrowed[chunks_borrowed_num - 1];
}

static inline void *nf_insert_new_chunk(uint8_t **p, size_t length,
                                        struct rte_mbuf *mbuf) {
  assert(chunks_borrowed_num < MAX_N_CHUNKS);
  assert(chunks_borrowed_num);

  // Do not really trace the ip options chunk, as it's length
  // is unknown statically
  CHUNK_LAYOUT_IMPL(*p, 1, NULL, 0, NULL, 0, "new_hdr");
  packet_insert_new_chunk((void **)p, length, chunks_borrowed,
                          &chunks_borrowed_num, mbuf);

  return chunks_borrowed[chunks_borrowed_num - 1];
}

static inline void *nf_get_borrowed_chunk(uint32_t chunk_i) {
  assert(chunk_i < chunks_borrowed_num);
  return chunks_borrowed[chunk_i];
}

static inline void nf_return_all_chunks(void *p) {
  while (chunks_borrowed_num != 0) {
    packet_return_chunk(p, chunks_borrowed[chunks_borrowed_num - 1]);
    chunks_borrowed_num--;
  }
}

static inline void nf_return_chunk(uint8_t **p) {
  if (chunks_borrowed_num != 0) {
    packet_return_chunk(*p, chunks_borrowed[chunks_borrowed_num - 1]);
    chunks_borrowed_num--;
  }
}

static inline struct rte_ether_hdr *nf_then_get_rte_ether_header(uint8_t **p) {
  CHUNK_LAYOUT_N(*p, rte_ether_hdr, rte_ether_fields, rte_ether_nested_fields);
  void *hdr = nf_borrow_next_chunk(p, sizeof(struct rte_ether_hdr));
  return (struct rte_ether_hdr *)hdr;
}

static inline struct rte_ipv4_hdr *
nf_then_get_rte_ipv4_header(void *rte_ether_header_, uint8_t **p,
                            uint8_t **ip_options) {
  struct rte_ether_hdr *rte_ether_header =
      (struct rte_ether_hdr *)rte_ether_header_;
  *ip_options = NULL;

  uint16_t unread_len = packet_get_unread_length(p);
  if ((!nf_has_rte_ipv4_header(rte_ether_header)) |
      (unread_len < sizeof(struct rte_ipv4_hdr))) {
    return NULL;
  }

  CHUNK_LAYOUT(p, rte_ipv4_hdr, rte_ipv4_fields);
  struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)nf_borrow_next_chunk(
      p, sizeof(struct rte_ipv4_hdr));

  uint8_t ihl = hdr->version_ihl & 0x0f;
  if ((ihl < IP_MIN_SIZE_WORDS) |
      (unread_len < rte_be_to_cpu_16(hdr->total_length))) {
    return NULL;
  }
  uint16_t ip_options_length = (ihl - IP_MIN_SIZE_WORDS) * WORD_SIZE;
  if ((ip_options_length != 0) &
      (unread_len - sizeof(struct rte_ipv4_hdr) >= ip_options_length)) {
    // Do not really trace the ip options chunk, as it's length
    // is unknown statically
    CHUNK_LAYOUT_IMPL(*p, 1, NULL, 0, NULL, 0, "ipv4_options");
    *ip_options = (uint8_t *)nf_borrow_next_chunk(p, ip_options_length);
  }
  return hdr;
}

static inline struct tcpudp_hdr *
nf_then_get_tcpudp_header(struct rte_ipv4_hdr *ip_header, uint8_t **p) {
  if ((!nf_has_tcpudp_header(ip_header)) |
      (packet_get_unread_length(p) < sizeof(struct tcpudp_hdr))) {
    return NULL;
  }
  CHUNK_LAYOUT(*p, tcpudp_hdr, tcpudp_fields);
  return (struct tcpudp_hdr *)nf_borrow_next_chunk(p,
                                                   sizeof(struct tcpudp_hdr));
}

/**********************************************
 *
 *                  NF-PARSE
 *
 **********************************************/

bool nf_parse_etheraddr(const char *str, struct rte_ether_addr *addr) {
  return sscanf(str, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
                addr->addr_bytes + 0, addr->addr_bytes + 1,
                addr->addr_bytes + 2, addr->addr_bytes + 3,
                addr->addr_bytes + 4, addr->addr_bytes + 5) == 6;
}

bool nf_parse_ipv4addr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;
  if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4) {
    *addr = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) |
            ((uint32_t)d << 0);
    return true;
  }
  return false;
}

/**********************************************
 *
 *                     NF
 *
 **********************************************/

#define FLOOD_FRAME ((uint16_t)-1)

struct nf_config;
struct rte_mbuf;

bool nf_init(void);
int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf);

extern struct nf_config config;
void nf_config_init(int argc, char **argv);
void nf_config_usage(void);
void nf_config_print(void);

#ifdef KLEE_VERIFICATION
#  include "libvig/models/hardware.h"
#  include "libvig/models/verified/vigor-time-control.h"
#  include <klee/klee.h>
#endif // KLEE_VERIFICATION

// NFOS declares its own main method
#ifdef NFOS
#  define MAIN nf_main
#else // NFOS
#  define MAIN main
#endif // NFOS

// Unverified support for batching, useful for performance comparisons
#ifndef VIGOR_BATCH_SIZE
#  define VIGOR_BATCH_SIZE 1
#endif

// More elaborate loop shape with annotations for verification
#ifdef KLEE_VERIFICATION
#  define VIGOR_LOOP_BEGIN                                                     \
    unsigned _vigor_lcore_id = 0; /* no multicore support for now */           \
    vigor_time_t _vigor_start_time = start_time();                             \
    int _vigor_loop_termination = klee_int("loop_termination");                \
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();                  \
    while (klee_induce_invariants() & _vigor_loop_termination) {               \
      nf_loop_iteration_border(_vigor_lcore_id, _vigor_start_time);            \
      vigor_time_t VIGOR_NOW = current_time();                                 \
      /* concretize the device to avoid leaking symbols into DPDK */           \
      uint16_t VIGOR_DEVICE =                                                  \
          klee_range(0, VIGOR_DEVICES_COUNT, "VIGOR_DEVICE");                  \
      concretize_devices(&VIGOR_DEVICE, VIGOR_DEVICES_COUNT);                  \
      stub_hardware_receive_packet(VIGOR_DEVICE);
#  define VIGOR_LOOP_END                                                       \
    stub_hardware_reset_receive(VIGOR_DEVICE);                                 \
    nf_loop_iteration_border(_vigor_lcore_id, VIGOR_NOW);                      \
    }
#else // KLEE_VERIFICATION
#  define VIGOR_LOOP_BEGIN                                                     \
    while (1) {                                                                \
      vigor_time_t VIGOR_NOW = current_time();                                 \
      unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();                \
      for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;      \
           VIGOR_DEVICE++) {
#  define VIGOR_LOOP_END                                                       \
    }                                                                          \
    }
#endif // KLEE_VERIFICATION

#if VIGOR_BATCH_SIZE == 1
// Queue sizes for receiving/transmitting packets
// NOT powers of 2 so that ixgbe doesn't use vector stuff
// but they have to be multiples of 8, and at least 32,
// otherwise the driver refuses to work
static const uint16_t RX_QUEUE_SIZE = 96;
static const uint16_t TX_QUEUE_SIZE = 96;
#else
// Do the opposite: we want batching!
static const uint16_t RX_QUEUE_SIZE = 128;
static const uint16_t TX_QUEUE_SIZE = 128;
#endif

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 256;

// Send the given packet to all devices except the packet's own
void flood(struct rte_mbuf *packet, uint16_t nb_devices) {
  rte_mbuf_refcnt_set(packet, nb_devices - 1);
  int total_sent = 0;
  uint16_t skip_device = packet->port;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device != skip_device) {
      total_sent += rte_eth_tx_burst(device, 0, &packet, 1);
    }
  }
  // should not happen, but in case we couldn't transmit, ensure the packet is
  // freed
  if (total_sent != nb_devices - 1) {
    rte_mbuf_refcnt_set(packet, 1);
    rte_pktmbuf_free(packet);
  }
}

// Initializes the given device using the given memory pool
static int nf_init_device(uint16_t device, struct rte_mempool *mbuf_pool) {
  int retval;

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf = { 0 };
  // device_conf.rxmode.hw_strip_crc = 1;

  // Configure the device (1, 1 == number of RX/TX queues)
  retval = rte_eth_dev_configure(device, 1, 1, &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up a TX queue (NULL == default config)
  retval = rte_eth_tx_queue_setup(device, 0, TX_QUEUE_SIZE,
                                  rte_eth_dev_socket_id(device), NULL);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up RX queues (NULL == default config)
  retval = rte_eth_rx_queue_setup(
      device, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL, mbuf_pool);
  if (retval != 0) {
    return retval;
  }

  // Start the device
  retval = rte_eth_dev_start(device);
  if (retval != 0) {
    return retval;
  }

  // Enable RX in promiscuous mode, just in case
  rte_eth_promiscuous_enable(device);
  if (rte_eth_promiscuous_get(device) != 1) {
    return retval;
  }

  return 0;
}

bool synapse_runtime_handle_pre_configure(env_ptr_t env) {
  synapse_env = env;
  synapse_runtime_config_reset();

  // Get a valid configuration for the runtime (i.e. devices, and bmv2 tables)
  if (!synapse_runtime_config(&synapse_config)) {
    SYNAPSE_DEBUG("Failed to configure the runtime");
    return false;
  }

  // Install singleton multicast group (the request is queued)
  if (!synapse_environment_queue_configure_multicast_group()) {
    SYNAPSE_ERROR("Could not queue multicast group");
    return false;
  }

  // Set all tags to 0
  synapse_runtime_pkt_out_reset();
  for (size_t i = 0; i < synapse_config.bmv2_tables_sz; i++) {
    synapse_config.bmv2_tables[i].tag = 0;
  }

  return synapse_runtime_pkt_out_update_tags_if_needed() &&
         synapse_environment_flush_pkt_out() && nf_init();
}

bool synapse_runtime_handle_packet_received() {
  stack_ptr_t stack = NULL;
  if (!synapse_environment_get_stack(&stack, 3)) {
    SYNAPSE_ERROR("The environment is corrupted");
    return false;
  }

  if (!synapse_runtime_pkt_in_populate_from_stack(stack)) {
    SYNAPSE_ERROR("The environment stack is corrupted");
    return false;
  }

  // Get the source device from the metadata
  static string_t src_device_str = { .str = "src_device", .sz = 10 };
  string_ptr_t src_device_encoded = NULL;
  if (!synapse_runtime_pkt_in_get_meta_by_name(src_device_str,
                                               &src_device_encoded)) {
    SYNAPSE_ERROR("Incoming packets must contain the ingress port");
    return false;
  }

  uint16_t src_device = synapse_decode_port(src_device_encoded);
  uint8_t *buffer = (uint8_t *)synapse_pkt_in.payload->str;
  uint16_t packet_length = synapse_pkt_in.payload->sz;
  vigor_time_t now = current_time();

  int dst_device = nf_process(src_device, &buffer, packet_length, now, NULL);

  if (!synapse_runtime_pkt_out_set_meta(src_device_str, *src_device_encoded)) {
    SYNAPSE_ERROR("Could not set metadata `src_device`");
    return false;
  }

  string_ptr_t dst_device_encoded;
  if (FLOOD_FRAME == dst_device) {
    SYNAPSE_INFO("Flooding");
    dst_device_encoded = synapse_encode_port(SYNAPSE_BROADCAST_PORT);

  } else {
    dst_device_encoded = synapse_encode_port(dst_device);
  }

  static string_t dst_device_str = { .str = "dst_device", .sz = 10 };
  if (!synapse_runtime_pkt_out_set_meta(dst_device_str, *dst_device_encoded)) {
    SYNAPSE_ERROR("Could not set metadata `dst_device`");
    return false;
  }

  if (!synapse_runtime_pkt_out_set_payload(synapse_pkt_in.payload)) {
    SYNAPSE_ERROR("Could not set payload");
    return false;
  }

  return synapse_runtime_pkt_out_update_tags_if_needed() &&
         synapse_environment_flush_pkt_out();
}

bool synapse_runtime_handle_idle_timeout_notification_received() {
  stack_ptr_t stack = NULL;
  if (!synapse_environment_get_stack(&stack, 2)) {
    SYNAPSE_ERROR("The environment is corrupted");
    return false;
  }

  size_t entriesSz = *((size_t *)synapse_runtime_wrappers_stack_pop(stack));
  p4_table_entry_ptr_t *entries = synapse_runtime_wrappers_stack_pop(stack);

  p4_table_entry_t entry;
  for (size_t i = 0; i < entriesSz; i++) {
    if (NULL == (entry = entries[i])) {
      return false;
    }

    if (!synapse_environment_queue_delete_table_entry(entry)) {
      return false;
    }
  }

  SYNAPSE_INFO("Deleted %d table entries", entriesSz);
  return true;
}

// Main worker method using the SyNAPSE Runtime
static void worker_main(void) {
  conn_ptr_t conn = synapse_runtime_connector_new(SYNAPSE_GRPC_ADDR);
  if (synapse_runtime_connector_configure(conn, SYNAPSE_JSON_PATH,
                                          SYNAPSE_P4INFO_PATH)) {
    synapse_runtime_connector_start_and_wait(conn);
  }

  synapse_runtime_connector_destroy(conn);
}

// Entry point
int MAIN(int argc, char **argv) {
  // Initialize the DPDK Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
  }
  argc -= ret;
  argv += ret;

  // Run!
  worker_main();

  return 0;
}