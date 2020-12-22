#include <inttypes.h>
// DPDK uses these but doesn't include them. :|
#include <linux/limits.h>
#include <sys/types.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include "libvig/verified/vigor-time.h"
#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/packet-io.h"
#include "libvig/verified/tcpudp_hdr.h"

#ifdef KLEE_VERIFICATION
#  include "libvig/models/hardware.h"
#  include "libvig/models/verified/vigor-time-control.h"
#  include "libvig/models/verified/packet-io-control.h"
#  include "libvig/models/str-descr.h"
#  include <klee/klee.h>
#  include <rte_ether.h>
#endif // KLEE_VERIFICATION
/***********************************************
SOURCE: nf-log.h
************************************************/
#ifdef KLEE_VERIFICATION
#  define NF_INFO(text, ...)
#else // KLEE_VERIFICATION
#  include <stdio.h>
#  include <inttypes.h>
#  define NF_INFO(text, ...)                                                   \
    printf(text "\n", ##__VA_ARGS__);                                          \
    fflush(stdout);
#endif // KLEE_VERIFICATION

#ifdef ENABLE_LOG
#  include <stdio.h>
#  include <inttypes.h>
#  define NF_DEBUG(text, ...)                                                  \
    fprintf(stderr, "DEBUG: " text "\n", ##__VA_ARGS__);                       \
    fflush(stderr);
#else // ENABLE_LOG
#  define NF_DEBUG(...)
#endif // ENABLE_LOG
/***********************************************
SOURCE: nf.h
************************************************/
#define FLOOD_FRAME ((uint16_t) -1)
/***********************************************
SOURCE: nf-util.h & nf-util.c & nf-rss.h
************************************************/
RTE_DEFINE_PER_LCORE(void **, chunks_borrowed);
RTE_DEFINE_PER_LCORE(size_t, chunks_borrowed_num);

// rte_ether
struct ether_addr;
struct ether_hdr;

#define IP_MIN_SIZE_WORDS 5
#define WORD_SIZE 4
#define MAX_PKT_BURST 32

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52
#define MAX_NUM_DEVICES 32 // this is quite arbitrary...

#define RETA_CONF_SIZE (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)
#define MAX_N_CHUNKS 100

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES];

struct lcore_conf {
  struct rte_mempool* mbuf_pool;
  uint16_t queue_id;
};

struct lcore_conf lcores_conf[RTE_MAX_LCORE];

#ifdef KLEE_VERIFICATION
static struct str_field_descr ether_fields[] = {
  { offsetof(struct ether_hdr, ether_type), sizeof(uint16_t), 0, "ether_type" },
  { offsetof(struct ether_hdr, d_addr), sizeof(struct ether_addr), 0,
    "d_addr" },
  { offsetof(struct ether_hdr, s_addr), sizeof(struct ether_addr), 0, "s_addr" }
};
static struct str_field_descr ipv4_fields[] = {
  { offsetof(struct ipv4_hdr, version_ihl), sizeof(uint8_t), 0, "version_ihl" },
  { offsetof(struct ipv4_hdr, type_of_service), sizeof(uint8_t), 0,
    "type_of_service" },
  { offsetof(struct ipv4_hdr, total_length), sizeof(uint16_t), 0,
    "total_length" },
  { offsetof(struct ipv4_hdr, packet_id), sizeof(uint16_t), 0, "packet_id" },
  { offsetof(struct ipv4_hdr, fragment_offset), sizeof(uint16_t), 0,
    "fragment_offset" },
  { offsetof(struct ipv4_hdr, time_to_live), sizeof(uint8_t), 0,
    "time_to_live" },
  { offsetof(struct ipv4_hdr, next_proto_id), sizeof(uint8_t), 0,
    "next_proto_id" },
  { offsetof(struct ipv4_hdr, hdr_checksum), sizeof(uint16_t), 0,
    "hdr_checksum" },
  { offsetof(struct ipv4_hdr, src_addr), sizeof(uint32_t), 0, "src_addr" },
  { offsetof(struct ipv4_hdr, dst_addr), sizeof(uint32_t), 0, "dst_addr" }
};
static struct str_field_descr tcpudp_fields[] = {
  { offsetof(struct tcpudp_hdr, src_port), sizeof(uint16_t), 0, "src_port" },
  { offsetof(struct tcpudp_hdr, dst_port), sizeof(uint16_t), 0, "dst_port" }
};
static struct nested_field_descr ether_nested_fields[] = {
  { offsetof(struct ether_hdr, d_addr), 0, sizeof(uint8_t), 6, "addr_bytes" },
  { offsetof(struct ether_hdr, s_addr), 0, sizeof(uint8_t), 6, "addr_bytes" }
};
#endif // KLEE_VERIFICATION

void reta_from_file(uint16_t reta[ETH_RSS_RETA_SIZE_512]) {
  int lcores = rte_lcore_count();

  FILE* fp;
  char* line = NULL;
  char* delim;
  size_t num_len;
  char* number;

  size_t len = 0;
  ssize_t read;

  fp = fopen("./lut.txt", "r");
  if (fp == NULL) {
    rte_exit(EXIT_FAILURE, "lut.txt not found");
  }

  int reta_lcores = 2;
  while ((read = getline(&line, &len, fp)) != -1) {
    if (reta_lcores == lcores) {
      break;
    }
    reta_lcores++;
  }
  fclose(fp);

  delim = line;
  number = (char*) malloc(sizeof(char) * read);
  for (uint16_t bucket = 0; bucket < ETH_RSS_RETA_SIZE_512; bucket++) {
    num_len = 0;
    while (*delim != ' ' && *delim != '\n') { number[num_len] = *delim; delim++; num_len++; }
    delim++;
    number[num_len] = '\0';

    reta[bucket] = atoi(number);
  }

  free(number);
  free(line);
}

void set_reta(uint16_t device, uint16_t reta[ETH_RSS_RETA_SIZE_512]) {
  struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(device, &dev_info);

  /* RETA setting */
  memset(reta_conf, 0, sizeof(reta_conf));

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
      reta_conf[bucket / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
  }

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
      uint32_t reta_id  = bucket / RTE_RETA_GROUP_SIZE;
      uint32_t reta_pos = bucket % RTE_RETA_GROUP_SIZE;
      reta_conf[reta_id].reta[reta_pos] = reta[bucket];
  }

  /* RETA update */
  rte_eth_dev_rss_reta_update(device, reta_conf, dev_info.reta_size);
}

void nf_util_init() {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void** *chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  (*chunks_borrowed_num_ptr) = 0;
  (*chunks_borrowed_ptr) = (void**) malloc(sizeof(void*) * MAX_N_CHUNKS);
}

bool nf_has_ipv4_header(struct ether_hdr *header) {
  return header->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4);
}

bool nf_has_tcpudp_header(struct ipv4_hdr *header) {
  // NOTE: Use non-short-circuiting version of OR, so that symbex doesn't fork
  //       since here we only care of it's UDP or TCP, not if it's a specific
  //       one
  return header->next_proto_id == IPPROTO_TCP |
         header->next_proto_id == IPPROTO_UDP;
}

#ifdef KLEE_VERIFICATION
void nf_set_ipv4_udptcp_checksum(struct ipv4_hdr *ip_header,
                                 struct tcpudp_hdr *l4_header, void *packet) {
  klee_trace_ret();
  klee_trace_param_u64((uint64_t)ip_header, "ip_header");
  klee_trace_param_u64((uint64_t)l4_header, "l4_header");
  klee_trace_param_u64((uint64_t)packet, "packet");
  // Make sure the packet pointer points to the TCPUDP continuation
  assert(packet_is_last_borrowed_chunk(packet, l4_header));
  ip_header->hdr_checksum = klee_int("checksum");
}
#else  // KLEE_VERIFICATION
void nf_set_ipv4_udptcp_checksum(struct ipv4_hdr *ip_header,
                                 struct tcpudp_hdr *l4_header, void *packet) {
  // Make sure the packet pointer points to the TCPUDP continuation
  // This check is exercised during verification, no need to repeat it.
  // void* payload = nf_borrow_next_chunk(packet,
  // rte_be_to_cpu_16(ip_header->total_length) - sizeof(struct tcpudp_hdr));
  // assert((char*)payload == ((char*)l4_header + sizeof(struct tcpudp_hdr)));

  ip_header->hdr_checksum = 0; // Assumed by cksum calculation
  if (ip_header->next_proto_id == IPPROTO_TCP) {
    struct tcp_hdr *tcp_header = (struct tcp_hdr *)l4_header;
    tcp_header->cksum = 0; // Assumed by cksum calculation
    tcp_header->cksum = rte_ipv4_udptcp_cksum(ip_header, tcp_header);
  } else if (ip_header->next_proto_id == IPPROTO_UDP) {
    struct udp_hdr *udp_header = (struct udp_hdr *)l4_header;
    udp_header->dgram_cksum = 0; // Assumed by cksum calculation
    udp_header->dgram_cksum = rte_ipv4_udptcp_cksum(ip_header, udp_header);
  }
  ip_header->hdr_checksum = rte_ipv4_cksum(ip_header);
}
#endif // KLEE_VERIFICATION

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

char *nf_mac_to_str(struct ether_addr *addr) {
  // format is xx:xx:xx:xx:xx:xx\0
  uint16_t buffer_size = 6 * 2 + 5 + 1; // FIXME: why dynamic alloc here?
  char *buffer = (char *)calloc(buffer_size, sizeof(char));
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_mac_to_str!");
  }

  snprintf(buffer, buffer_size, "%02X:%02X:%02X:%02X:%02X:%02X", addr->addr_bytes[0],
           addr->addr_bytes[1], addr->addr_bytes[2],
           addr->addr_bytes[3], addr->addr_bytes[4],
           addr->addr_bytes[5]);

  return buffer;
}

char *nf_ipv4_to_str(uint32_t addr) {
  // format is xxx.xxx.xxx.xxx\0
  uint16_t buffer_size = 4 * 3 + 3 + 1;
  char *buffer = (char *)calloc(buffer_size,
                                sizeof(char)); // FIXME: why dynamic alloc here?
  if (buffer == NULL) {
    rte_exit(EXIT_FAILURE, "Out of memory in nf_ipv4_to_str!");
  }

  snprintf(buffer, buffer_size, "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
           addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
           (addr >> 24) & 0xFF);
  return buffer;
}

RTE_DECLARE_PER_LCORE(void **, chunks_borrowed);
RTE_DECLARE_PER_LCORE(size_t, chunks_borrowed_num);

static inline void *nf_borrow_next_chunk(void *p, size_t length) {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void** *chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  assert(*chunks_borrowed_num_ptr < MAX_N_CHUNKS);
  void *chunk;
  packet_borrow_next_chunk(p, length, &chunk);
  (*chunks_borrowed_ptr)[*chunks_borrowed_num_ptr] = chunk;
  (*chunks_borrowed_num_ptr)++;
  return chunk;
}

#ifdef KLEE_VERIFICATION
#  define CHUNK_LAYOUT_IMPL(pkt, len, fields, n_fields, nests, n_nests, tag)   \
    packet_set_next_chunk_layout(pkt, len, fields, n_fields, nests, n_nests,   \
                                 tag)
#else // KLEE_VERIFICATION
#  define CHUNK_LAYOUT_IMPL(pkt, len, fields, n_fields, nests, n_nests, tag)   \
    /*nothing*/
#endif // KLEE_VERIFICATION

#define CHUNK_LAYOUT_N(pkt, str_name, fields, nests)                           \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,                      \
                    sizeof(fields) / sizeof(fields[0]), nests,                 \
                    sizeof(nests) / sizeof(nests[0]), #str_name);

#define CHUNK_LAYOUT(pkt, str_name, fields)                                    \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,                      \
                    sizeof(fields) / sizeof(fields[0]), NULL, 0, #str_name);

static inline void nf_return_all_chunks(void *p) {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void** *chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  do {
    (*chunks_borrowed_num_ptr)--;
    packet_return_chunk(p, (*chunks_borrowed_ptr)[*chunks_borrowed_num_ptr]);
  } while ((*chunks_borrowed_num_ptr) != 0);
}

static inline struct ether_hdr *nf_then_get_ether_header(void *p) {
  CHUNK_LAYOUT_N(p, ether_hdr, ether_fields, ether_nested_fields);
  void *hdr = nf_borrow_next_chunk(p, sizeof(struct ether_hdr));
  return (struct ether_hdr *)hdr;
}

static inline struct ipv4_hdr *
nf_then_get_ipv4_header(void *ether_header_, void *p, uint8_t **ip_options) {  
  struct ether_hdr *ether_header = (struct ether_hdr *)ether_header_;
  *ip_options = NULL;

  uint16_t unread_len = packet_get_unread_length(p);
  if ((!nf_has_ipv4_header(ether_header)) |
      (unread_len < sizeof(struct ipv4_hdr))) {
    return NULL;
  }

  CHUNK_LAYOUT(p, ipv4_hdr, ipv4_fields);
  struct ipv4_hdr *hdr =
      (struct ipv4_hdr *)nf_borrow_next_chunk(p, sizeof(struct ipv4_hdr));

  uint8_t ihl = hdr->version_ihl & 0x0f;
  if ((ihl < IP_MIN_SIZE_WORDS) |
      (unread_len < rte_be_to_cpu_16(hdr->total_length))) {
    return NULL;
  }
  uint16_t ip_options_length = (ihl - IP_MIN_SIZE_WORDS) * WORD_SIZE;
  if ((ip_options_length != 0) &
      (unread_len - sizeof(struct ipv4_hdr) >= ip_options_length)) {
    // Do not really trace the ip options chunk, as it's length
    // is unknown statically
    CHUNK_LAYOUT_IMPL(p, 1, NULL, 0, NULL, 0, "ipv4_options");
    *ip_options = (uint8_t *)nf_borrow_next_chunk(p, ip_options_length);
  }
  return hdr;
}

static inline struct tcpudp_hdr *
nf_then_get_tcpudp_header(struct ipv4_hdr *ip_header, void *p) {
  if ((!nf_has_tcpudp_header(ip_header)) |
      (packet_get_unread_length(p) < sizeof(struct tcpudp_hdr))) {
    return NULL;
  }
  CHUNK_LAYOUT(p, tcpudp_hdr, tcpudp_fields);
  return (struct tcpudp_hdr *)nf_borrow_next_chunk(p,
                                                   sizeof(struct tcpudp_hdr));
}

static inline uint16_t nf_receive_packet(uint16_t src_device,
                                     uint16_t queue_id,
                                     struct rte_mbuf **mbuf) {
  return rte_eth_rx_burst(src_device, queue_id, mbuf, MAX_PKT_BURST);
}

static inline void nf_update_packet_state_total_length(struct rte_mbuf **mbuf, uint16_t burst_id) {
  // TODO: for multi-mbuf packets, make sure to differentiate
  // between pkt_len and data_len
  packet_state_total_length(rte_pktmbuf_mtod(mbuf[burst_id], char*), &(*mbuf[burst_id]).pkt_len);
}

static inline void nf_free_packet(struct rte_mbuf *mbuf) {
  rte_pktmbuf_free(mbuf);
}

static inline void nf_send_packet(struct rte_mbuf *mbuf, int dst_device, uint16_t queue_id) {
  uint16_t actual_tx_len = rte_eth_tx_burst(dst_device, queue_id, &mbuf, 1);
  if (actual_tx_len == 0) {
    rte_pktmbuf_free(mbuf);
  }
}
/***********************************************
SOURCE: nf specific functions
************************************************/
bool nf_init();
int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, uint64_t now);
/***********************************************
SOURCE: nf.c
************************************************/
#ifdef NFOS
#  define MAIN nf_main
#else // NFOS
#  define MAIN main
#endif // NFOS

#ifdef KLEE_VERIFICATION
#  define VIGOR_LOOP_BEGIN                                                     \
    unsigned _vigor_lcore_id = rte_lcore_id();                                 \
    vigor_time_t _vigor_start_time = start_time();                             \
    int _vigor_loop_termination = klee_int("loop_termination");                \
    unsigned VIGOR_DEVICES_COUNT;                                              \
    klee_possibly_havoc(&VIGOR_DEVICES_COUNT, sizeof(VIGOR_DEVICES_COUNT),     \
                        "VIGOR_DEVICES_COUNT");                                \
    vigor_time_t VIGOR_NOW;                                                    \
    klee_possibly_havoc(&VIGOR_NOW, sizeof(VIGOR_NOW), "VIGOR_NOW");           \
    unsigned VIGOR_DEVICE;                                                     \
    klee_possibly_havoc(&VIGOR_DEVICE, sizeof(VIGOR_DEVICE), "VIGOR_DEVICE");  \
    unsigned _d;                                                               \
    klee_possibly_havoc(&_d, sizeof(_d), "_d");                                \
    while (klee_induce_invariants() & _vigor_loop_termination) {               \
      nf_loop_iteration_border(_vigor_lcore_id, _vigor_start_time);            \
      VIGOR_NOW = current_time();                                              \
      /* concretize the device to avoid leaking symbols into DPDK */           \
      VIGOR_DEVICES_COUNT = rte_eth_dev_count();                               \
      VIGOR_DEVICE = klee_range(0, VIGOR_DEVICES_COUNT, "VIGOR_DEVICE");       \
      for (_d = 0; _d < VIGOR_DEVICES_COUNT; _d++)                             \
        if (VIGOR_DEVICE == _d) {                                              \
          VIGOR_DEVICE = _d;                                                   \
          break;                                                               \
        }                                                                      \
      stub_hardware_receive_packet(VIGOR_DEVICE);
#  define VIGOR_LOOP_END                                                       \
    stub_hardware_reset_receive(VIGOR_DEVICE);                                 \
    nf_loop_iteration_border(_vigor_lcore_id, VIGOR_NOW);                      \
    }
#else // KLEE_VERIFICATION
#  define VIGOR_LOOP_BEGIN                                                     \
    while (1) {                                                                \
      vigor_time_t VIGOR_NOW = current_time();                                 \
      unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count();                      \
      for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;      \
           VIGOR_DEVICE++) {
#  define VIGOR_LOOP_END                                                       \
    }                                                                          \
    }
#endif // KLEE_VERIFICATION

// Number of RX/TX queues
static const uint16_t RX_QUEUES_COUNT = 1;
static const uint16_t TX_QUEUES_COUNT = 1;

// Queue sizes for receiving/transmitting packets
// NOT powers of 2 so that ixgbe doesn't use vector stuff
// but they have to be multiples of 8, and at least 32, otherwise the driver
// refuses
static const uint16_t RX_QUEUE_SIZE = 96;
static const uint16_t TX_QUEUE_SIZE = 96;

void flood(struct rte_mbuf *frame, uint16_t skip_device, uint16_t nb_devices, uint16_t queue_id) {
  rte_mbuf_refcnt_set(frame, nb_devices - 1);
  int total_sent = 0;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device == skip_device)
      continue;
    total_sent += rte_eth_tx_burst(device, queue_id, &frame, 1);
  }
  if (total_sent != nb_devices - 1) {
    rte_pktmbuf_free(frame);
  }
}

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 256;

// --- Initialization ---
static int nf_init_device(uint16_t device, struct rte_mempool** mbuf_pools) {
  int retval;
  const uint16_t num_queues = rte_lcore_count();

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf;
  memset(&device_conf, 0, sizeof(struct rte_eth_conf));

  device_conf.rxmode.hw_strip_crc = 1;
  device_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
  device_conf.rx_adv_conf.rss_conf = rss_conf[device];

  // Configure the device
  retval = rte_eth_dev_configure(device, num_queues, num_queues,
                                 &device_conf);
  if (retval != 0) {
    return retval;
  }

  uint16_t nb_rxd = 136;
  uint16_t nb_txd = 152;

  retval = rte_eth_dev_adjust_nb_rx_tx_desc(device, &nb_rxd, &nb_txd);

  if (retval != 0) {
    return retval;
  }

  // Allocate and set up TX queues
  for (int txq = 0; txq < num_queues; txq++) {
    retval = rte_eth_tx_queue_setup(device, txq, nb_txd,
                                    rte_eth_dev_socket_id(device), NULL);
    if (retval != 0) {
      return retval;
    }
  }

  unsigned lcore_id;
  int rxq = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    // Allocate and set up RX queues
    lcores_conf[lcore_id].queue_id = rxq;
    retval = rte_eth_rx_queue_setup(device, rxq, nb_rxd,
                                    rte_eth_dev_socket_id(device),
                                    NULL,
                                    mbuf_pools[rxq]);
    if (retval != 0) {
      return retval;
    }

    rxq++;
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

  if (rte_lcore_count() > 1) {
    uint16_t reta[ETH_RSS_RETA_SIZE_512];
    reta_from_file(reta);
    set_reta(device, reta);
  }

  return 0;
}

// --- Per-core work ---

static void lcore_main(void) {
  const unsigned lcore_id = rte_lcore_id();
  const uint16_t queue_id = lcores_conf[lcore_id].queue_id;

  for (uint16_t device = 0; device < rte_eth_dev_count(); device++) {
    if (rte_eth_dev_socket_id(device) > 0 &&
        rte_eth_dev_socket_id(device) != (int)rte_socket_id()) {
      NF_INFO("Device %" PRIu8 " is on remote NUMA node to polling thread.",
              device);
    }
  }

  nf_util_init();
  packet_io_init();

  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  NF_INFO("Core %u using queue %u forwarding packets.", lcore_id, (unsigned)queue_id);

  VIGOR_LOOP_BEGIN
    struct rte_mbuf *mbuf[MAX_PKT_BURST];
    uint16_t nb_rx = nf_receive_packet(VIGOR_DEVICE, queue_id, mbuf);
    if (nb_rx == 0) {
      continue;
    }

    for (uint16_t rx_id = 0; rx_id < nb_rx; rx_id++) {
      nf_update_packet_state_total_length(mbuf, rx_id);
      uint8_t* packet = rte_pktmbuf_mtod(mbuf[rx_id], uint8_t*);
      NF_DEBUG("lcore %u hash 0x%08x", lcore_id, mbuf[rx_id]->hash.rss);
      uint16_t dst_device = nf_process(mbuf[rx_id]->port, packet, mbuf[rx_id]->data_len, VIGOR_NOW);
      nf_return_all_chunks(packet);

      if (dst_device == VIGOR_DEVICE) {
        nf_free_packet(mbuf[rx_id]);
      } else if (dst_device == FLOOD_FRAME) {
        flood(mbuf[rx_id], VIGOR_DEVICE, VIGOR_DEVICES_COUNT, queue_id);
      } else {
        concretize_devices(&dst_device, rte_eth_dev_count());
        nf_send_packet(mbuf[rx_id], dst_device, queue_id);
      }
    }
  VIGOR_LOOP_END
}

uint8_t hash_key[RSS_HASH_KEY_LENGTH] = {
  0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
  0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
  0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
  0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
  0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {
  {
    .rss_key = hash_key,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
  },
  {
    .rss_key = hash_key,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP
  }
};

// --- Main ---
int main(int argc, char *argv[]) {
  // Initialize the Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
  }
  argc -= ret;
  argv += ret;

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count();

  char MBUF_POOL_NAME[20];
  struct rte_mempool **mbuf_pools;
  mbuf_pools = (struct rte_mempool**) malloc(sizeof(struct rte_mempool*) * rte_lcore_count());

  unsigned lcore_id;
  unsigned lcore_idx = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    sprintf(MBUF_POOL_NAME, "MEMORY_POOL_%u", lcore_idx);

    mbuf_pools[lcore_idx] = rte_pktmbuf_pool_create(
                            MBUF_POOL_NAME, // name
                            MEMPOOL_BUFFER_COUNT * nb_devices, // #elements
                            MBUF_CACHE_SIZE, // cache size (per-lcore)
                            0, // application private area size
                            RTE_MBUF_DEFAULT_BUF_SIZE, // data buffer size
                            // rte_lcore_to_socket_id(lcore_id) // socket ID
                            0
    );

    if (mbuf_pools[lcore_idx] == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
               rte_strerror(rte_errno));
    }

    lcore_idx++;
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    ret = nf_init_device(device, mbuf_pools);
    if (ret == 0) {
      NF_INFO("Initialized device %" PRIu16 ".", device);
    } else {
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ", ret=%d", device,
               ret);
    }
  }

  // Run!
  // ...in single-threaded mode, that is.

  // ... UNTIL NOW

  // call on each lcore
  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    rte_eal_remote_launch((lcore_function_t *)lcore_main, NULL, lcore_id);
  }

  /* call it on master lcore too */
  lcore_main();

  return 0;
}

bool nf_init() {
  return 1;
}

int nf_process(uint16_t device, uint8_t* buffer, uint16_t buffer_length, uint64_t now) {
  struct ether_hdr* ether_header;
  packet_borrow_next_chunk(buffer, 14, (void**)&ether_header);

  // ../vigor/vignop/klee-last/test000003.call_path
  if (device) {
    ether_header->d_addr.addr_bytes[0] = 1;
    ether_header->d_addr.addr_bytes[1] = 35;
    ether_header->d_addr.addr_bytes[2] = 69;
    ether_header->d_addr.addr_bytes[3] = 103;
    ether_header->d_addr.addr_bytes[4] = 137;
    ether_header->d_addr.addr_bytes[5] = 0;
    ether_header->s_addr.addr_bytes[0] = -1 + (ether_header->ether_type & 15);
    ether_header->s_addr.addr_bytes[1] = 0;
    ether_header->s_addr.addr_bytes[2] = 0;
    ether_header->s_addr.addr_bytes[3] = 0;
    ether_header->s_addr.addr_bytes[4] = 0;
    ether_header->s_addr.addr_bytes[5] = 0;
    return 0;
  }

  // ../vigor/vignop/klee-last/test000005.call_path
  else {
    ether_header->d_addr.addr_bytes[0] = 1;
    ether_header->d_addr.addr_bytes[1] = 35;
    ether_header->d_addr.addr_bytes[2] = 69;
    ether_header->d_addr.addr_bytes[3] = 103;
    ether_header->d_addr.addr_bytes[4] = 137;
    ether_header->d_addr.addr_bytes[5] = 1;
    ether_header->s_addr.addr_bytes[0] = 0;
    ether_header->s_addr.addr_bytes[1] = 0;
    ether_header->s_addr.addr_bytes[2] = 0;
    ether_header->s_addr.addr_bytes[3] = 0;
    ether_header->s_addr.addr_bytes[4] = 0;
    ether_header->s_addr.addr_bytes[5] = 0;
    return 1;
  } // !device

}
