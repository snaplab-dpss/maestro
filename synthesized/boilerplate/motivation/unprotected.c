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

RTE_DEFINE_PER_LCORE(size_t, global_total_length);
RTE_DEFINE_PER_LCORE(size_t, global_read_length);

void packet_io_init() {
  size_t *global_read_length_ptr = &RTE_PER_LCORE(global_read_length);
  (*global_read_length_ptr) = 0;
}

void packet_state_total_length(void *p, uint32_t *len) {
  size_t *global_total_length_ptr = &RTE_PER_LCORE(global_total_length);
  (*global_total_length_ptr) = *len;
}

void packet_borrow_next_chunk(void *p, size_t length, void **chunk) {
  size_t *global_read_length_ptr = &RTE_PER_LCORE(global_read_length);
  *chunk = (char *)p + (*global_read_length_ptr);
  (*global_read_length_ptr) += length;
}

void packet_return_chunk(void *p, void *chunk) {
  size_t *global_read_length_ptr = &RTE_PER_LCORE(global_read_length);
  (*global_read_length_ptr) = (uint32_t)((int8_t *)chunk - (int8_t *)p);
}

uint32_t packet_get_unread_length(void *p) {
  size_t *global_total_length_ptr = &RTE_PER_LCORE(global_total_length);
  size_t *global_read_length_ptr = &RTE_PER_LCORE(global_read_length);
  return (*global_total_length_ptr) - (*global_read_length_ptr);
}

/**********************************************
 *
 *                  NF-RSS
 *
 **********************************************/

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52
#define MAX_NUM_DEVICES 32  // this is quite arbitrary...

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES];

struct lcore_conf {
  struct rte_mempool *mbuf_pool;
  uint16_t queue_id;
};

struct lcore_conf lcores_conf[RTE_MAX_LCORE];

/**********************************************
 *
 *                  NF-LOG
 *
 **********************************************/

#define NF_INFO(text, ...)          \
  printf(text "\n", ##__VA_ARGS__); \
  fflush(stdout);

#ifdef ENABLE_LOG
#define NF_DEBUG(text, ...)                            \
  fprintf(stderr, "DEBUG: " text "\n", ##__VA_ARGS__); \
  fflush(stderr);
#else  // ENABLE_LOG
#define NF_DEBUG(...)
#endif  // ENABLE_LOG

/**********************************************
 *
 *                  NF-UTIL
 *
 **********************************************/

// rte_ether
struct rte_ether_addr;
struct rte_ether_hdr;

#define IP_MIN_SIZE_WORDS 5
#define WORD_SIZE 4

#define MAX_N_CHUNKS 100

// this is here just to allow compilation
void *chunks_borrowed[MAX_N_CHUNKS];
size_t chunks_borrowed_num = 0;

RTE_DEFINE_PER_LCORE(void **, chunks_borrowed);
RTE_DEFINE_PER_LCORE(size_t, chunks_borrowed_num);

// this is doing nothing here, just making compilation easier
RTE_DEFINE_PER_LCORE(bool, write_attempt);
RTE_DEFINE_PER_LCORE(bool, write_state);

void nf_util_init() {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void ***chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  (*chunks_borrowed_num_ptr) = 0;
  (*chunks_borrowed_ptr) =
      (void **)rte_malloc(NULL, sizeof(void *) * MAX_N_CHUNKS, 64);
}

static inline void *nf_borrow_next_chunk(void *p, size_t length) {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void ***chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  assert(*chunks_borrowed_num_ptr < MAX_N_CHUNKS);
  void *chunk;
  packet_borrow_next_chunk(p, length, &chunk);
  (*chunks_borrowed_ptr)[*chunks_borrowed_num_ptr] = chunk;
  (*chunks_borrowed_num_ptr)++;
  return chunk;
}

#define CHUNK_LAYOUT_IMPL(pkt, len, fields, n_fields, nests, n_nests, \
                          tag) /*nothing*/

#define CHUNK_LAYOUT_N(pkt, str_name, fields, nests)           \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,      \
                    sizeof(fields) / sizeof(fields[0]), nests, \
                    sizeof(nests) / sizeof(nests[0]), #str_name);

#define CHUNK_LAYOUT(pkt, str_name, fields)               \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields, \
                    sizeof(fields) / sizeof(fields[0]), NULL, 0, #str_name);

static inline void nf_return_all_chunks(void *p) {
  size_t *chunks_borrowed_num_ptr = &RTE_PER_LCORE(chunks_borrowed_num);
  void ***chunks_borrowed_ptr = &RTE_PER_LCORE(chunks_borrowed);

  while ((*chunks_borrowed_num_ptr) != 0) {
    (*chunks_borrowed_num_ptr)--;
    packet_return_chunk(p, (*chunks_borrowed_ptr)[*chunks_borrowed_num_ptr]);
  }
}

static inline struct rte_ether_hdr *nf_then_get_rte_ether_header(void *p) {
  CHUNK_LAYOUT_N(p, rte_ether_hdr, rte_ether_fields, rte_ether_nested_fields);
  void *hdr = nf_borrow_next_chunk(p, sizeof(struct rte_ether_hdr));
  return (struct rte_ether_hdr *)hdr;
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

static inline struct rte_ipv4_hdr *nf_then_get_rte_ipv4_header(
    void *rte_ether_header_, void *p, uint8_t **ip_options) {
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
    CHUNK_LAYOUT_IMPL(p, 1, NULL, 0, NULL, 0, "ipv4_options");
    *ip_options = (uint8_t *)nf_borrow_next_chunk(p, ip_options_length);
  }
  return hdr;
}

static inline struct tcpudp_hdr *nf_then_get_tcpudp_header(
    struct rte_ipv4_hdr *ip_header, void *p) {
  if ((!nf_has_tcpudp_header(ip_header)) |
      (packet_get_unread_length(p) < sizeof(struct tcpudp_hdr))) {
    return NULL;
  }
  CHUNK_LAYOUT(p, tcpudp_hdr, tcpudp_fields);
  return (struct tcpudp_hdr *)nf_borrow_next_chunk(p,
                                                   sizeof(struct tcpudp_hdr));
}

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

#define RETA_CONF_SIZE (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

typedef struct {
  uint16_t tables[RTE_MAX_LCORE][ETH_RSS_RETA_SIZE_512];
  bool set;
} retas_t;

retas_t retas_per_device[MAX_NUM_DEVICES];

void init_retas();

void set_reta(uint16_t device) {
  unsigned lcores = rte_lcore_count();

  if (lcores <= 1 || !retas_per_device[device].set) {
    return;
  }

  struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(device, &dev_info);

  /* RETA setting */
  memset(reta_conf, 0, sizeof(reta_conf));

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
    reta_conf[bucket / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
  }

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
    uint32_t reta_id = bucket / RTE_RETA_GROUP_SIZE;
    uint32_t reta_pos = bucket % RTE_RETA_GROUP_SIZE;
    reta_conf[reta_id].reta[reta_pos] =
        retas_per_device[device].tables[lcores - 2][bucket];
  }

  /* RETA update */
  rte_eth_dev_rss_reta_update(device, reta_conf, dev_info.reta_size);
}

/**********************************************
 *
 *                  NF
 *
 **********************************************/

bool nf_init(void);
int nf_process(uint16_t device, uint8_t *buffer, uint16_t packet_length,
               vigor_time_t now);

#define FLOOD_FRAME ((uint16_t) - 1)

// NFOS declares its own main method
#ifdef NFOS
#define MAIN nf_main
#else  // NFOS
#define MAIN main
#endif  // NFOS

// Unverified support for batching, useful for performance comparisons
#define VIGOR_BATCH_SIZE 32

#define VIGOR_LOOP_BEGIN                                                \
  while (1) {                                                           \
    vigor_time_t VIGOR_NOW = current_time();                            \
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();           \
    for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT; \
         VIGOR_DEVICE++) {
#define VIGOR_LOOP_END

// Do the opposite: we want batching!
static const uint16_t RX_QUEUE_SIZE = 256;
static const uint16_t TX_QUEUE_SIZE = 256;

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 512;

// Send the given packet to all devices except the packet's own
void flood(struct rte_mbuf *packet, uint16_t nb_devices, uint16_t queue_id) {
  rte_mbuf_refcnt_set(packet, nb_devices - 1);
  int total_sent = 0;
  uint16_t skip_device = packet->port;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device != skip_device) {
      total_sent += rte_eth_tx_burst(device, queue_id, &packet, 1);
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
static int nf_init_device(uint16_t device, struct rte_mempool **mbuf_pools) {
  int retval;
  const uint16_t num_queues = rte_lcore_count();

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf = {0};
  // device_conf.rxmode.hw_strip_crc = 1;
  device_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
  device_conf.rx_adv_conf.rss_conf = rss_conf[device];

  retval = rte_eth_dev_configure(device, num_queues, num_queues, &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up a TX queue (NULL == default config)
  retval = rte_eth_tx_queue_setup(device, 0, TX_QUEUE_SIZE,
                                  rte_eth_dev_socket_id(device), NULL);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up TX queues
  for (int txq = 0; txq < num_queues; txq++) {
    retval = rte_eth_tx_queue_setup(device, txq, TX_QUEUE_SIZE,
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
    retval = rte_eth_rx_queue_setup(device, rxq, RX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device), NULL,
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

  set_reta(device);

  return 0;
}

static void worker_main(void) {
  const unsigned lcore_id = rte_lcore_id();
  const uint16_t queue_id = lcores_conf[lcore_id].queue_id;

  nf_util_init();
  packet_io_init();

  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  NF_INFO("Core %u forwarding packets.", rte_lcore_id());

  if (rte_eth_dev_count_avail() != 2) {
    printf(
        "We assume there will be exactly 2 devices for our simple batching "
        "implementation.");
    exit(1);
  }
  NF_INFO("Running with batches, this code is unverified!");

  while (1) {
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();
    for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;
         VIGOR_DEVICE++) {
      struct rte_mbuf *mbufs[VIGOR_BATCH_SIZE];
      uint16_t rx_count =
          rte_eth_rx_burst(VIGOR_DEVICE, queue_id, mbufs, VIGOR_BATCH_SIZE);

      struct rte_mbuf *mbufs_to_send[VIGOR_BATCH_SIZE];
      uint16_t tx_count = 0;
      for (uint16_t n = 0; n < rx_count; n++) {
        uint8_t *data = rte_pktmbuf_mtod(mbufs[n], uint8_t *);
        packet_state_total_length(data, &(mbufs[n]->pkt_len));
        vigor_time_t VIGOR_NOW = current_time();
        uint16_t dst_device =
            nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, VIGOR_NOW);
        nf_return_all_chunks(data);

        if (dst_device == VIGOR_DEVICE) {
          rte_pktmbuf_free(mbufs[n]);
        } else if (dst_device == FLOOD_FRAME) {
          flood(mbufs[n], VIGOR_DEVICES_COUNT, queue_id);
        } else {  // includes flood when 2 devices, which is equivalent to just
                  // a
                  // send
          mbufs_to_send[tx_count] = mbufs[n];
          tx_count++;
        }
      }

      uint16_t sent_count =
          rte_eth_tx_burst(1 - VIGOR_DEVICE, queue_id, mbufs_to_send, tx_count);
      for (uint16_t n = sent_count; n < tx_count; n++) {
        rte_pktmbuf_free(mbufs[n]);  // should not happen, but we're in the
                                     // unverified case anyway
      }
    }
  }
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

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count_avail();

  init_retas();

  char MBUF_POOL_NAME[20];
  struct rte_mempool **mbuf_pools;
  mbuf_pools = (struct rte_mempool **)rte_malloc(
      NULL, sizeof(struct rte_mempool *) * rte_lcore_count(), 64);

  unsigned lcore_id;
  unsigned lcore_idx = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    sprintf(MBUF_POOL_NAME, "MEMORY_POOL_%u", lcore_idx);

    mbuf_pools[lcore_idx] =
        rte_pktmbuf_pool_create(MBUF_POOL_NAME,                     // name
                                MEMPOOL_BUFFER_COUNT * nb_devices,  // #elements
                                MBUF_CACHE_SIZE,  // cache size (per-lcore)
                                0,  // application private area size
                                RTE_MBUF_DEFAULT_BUF_SIZE,  // data buffer size
                                rte_socket_id()             // socket ID
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
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ": %d", device, ret);
    }
  }

  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    rte_eal_remote_launch((lcore_function_t *)worker_main, NULL, lcore_id);
  }

  worker_main();

  return 0;
}

uint8_t hash_key_0[RSS_HASH_KEY_LENGTH] = {
    0x6,  0x6a, 0xdb, 0xff, 0x5c, 0xdf, 0xd8, 0xaa, 0xf3, 0x4f, 0x73,
    0x23, 0x96, 0x8b, 0x4c, 0x3b, 0x16, 0x37, 0x9f, 0x35, 0xdc, 0x18,
    0x26, 0x38, 0xba, 0x90, 0x2d, 0xf4, 0x11, 0xe6, 0xcb, 0x17, 0x51,
    0xa6, 0x16, 0xad, 0x85, 0xee, 0x57, 0x78, 0x3d, 0xca, 0x9c, 0xd3,
    0x55, 0xe8, 0xe,  0x6b, 0x1f, 0xae, 0xa1, 0xfb};
uint8_t hash_key_1[RSS_HASH_KEY_LENGTH] = {
    0xfb, 0xfe, 0xdc, 0x17, 0x1d, 0x68, 0x9d, 0xe7, 0x7b, 0xd0, 0xd1,
    0x44, 0xc,  0xcc, 0xdc, 0xbd, 0x1d, 0x8,  0xd6, 0x3f, 0x14, 0xc1,
    0xd5, 0x15, 0x50, 0x2a, 0xb9, 0xc0, 0x9a, 0x53, 0xba, 0x95, 0x51,
    0x97, 0xac, 0x6e, 0xff, 0x4a, 0x56, 0x7a, 0x1a, 0x27, 0xbe, 0x27,
    0xf4, 0x9b, 0xe4, 0x11, 0xa3, 0xba, 0x50, 0xb7};

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {
    {.rss_key = hash_key_0,
     .rss_key_len = RSS_HASH_KEY_LENGTH,
     .rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP},
    {.rss_key = hash_key_1,
     .rss_key_len = RSS_HASH_KEY_LENGTH,
     .rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP}};

typedef struct {
  uint64_t counter;
} __attribute__((aligned(64))) counter_t;

counter_t c1;
counter_t c2;
counter_t c3;
counter_t c4;
counter_t c5;
counter_t c6;

bool nf_init(void) {
  if (rte_lcore_id() == rte_get_master_lcore()) {
    c1.counter = 0;
    c2.counter = 0;
    c3.counter = 0;
    c4.counter = 0;
    c5.counter = 0;
    c6.counter = 0;
  }

  return true;
}

int nf_process(uint16_t device, uint8_t *buffer, uint16_t buffer_length,
               vigor_time_t now) {
  struct rte_ether_hdr *ether_header = nf_borrow_next_chunk(buffer, 14u);

  uint8_t *ip_options;
  struct rte_ipv4_hdr *rte_ipv4_header =
      nf_then_get_rte_ipv4_header(ether_header, buffer, &ip_options);
  if (rte_ipv4_header == NULL) {
    NF_DEBUG("Not IPv4, dropping");
    return device;
  }

  struct tcpudp_hdr *tcpudp_header =
      nf_then_get_tcpudp_header(rte_ipv4_header, buffer);
  if (tcpudp_header == NULL) {
    NF_DEBUG("Not TCP/UDP, dropping");
    return device;
  }

  uint64_t core_specific_load = 1;
  for (int i = 0; i < 200; i++) {
    core_specific_load = (core_specific_load * 13) % 17;
  }

  c1.counter += core_specific_load;
  uint64_t r1 = c1.counter;

  c2.counter += core_specific_load;
  uint64_t r2 = c2.counter;

  c3.counter += core_specific_load;
  uint64_t r3 = c3.counter;

  c4.counter += core_specific_load;
  uint64_t r4 = c4.counter;

  c5.counter += core_specific_load;
  uint64_t r5 = c5.counter;

  c6.counter += core_specific_load;
  uint64_t r6 = c6.counter;

  // test000003
  if (device) {
    ether_header->d_addr.addr_bytes[0ul] = 1u;
    ether_header->d_addr.addr_bytes[1ul] = 35u;
    ether_header->d_addr.addr_bytes[2ul] = 69u;
    ether_header->d_addr.addr_bytes[3ul] = 103u;
    ether_header->d_addr.addr_bytes[4ul] = 137u;
    ether_header->d_addr.addr_bytes[5ul] = 0u;
    ether_header->s_addr.addr_bytes[0ul] = 0u;
    ether_header->s_addr.addr_bytes[1ul] = 0u;
    ether_header->s_addr.addr_bytes[2ul] = 0u;
    ether_header->s_addr.addr_bytes[3ul] = 0u;
    ether_header->s_addr.addr_bytes[4ul] = 0u;
    ether_header->s_addr.addr_bytes[5ul] = 0u;
    return 0;
  }

  // test000005
  else {
    ether_header->d_addr.addr_bytes[0ul] = 1u;
    ether_header->d_addr.addr_bytes[1ul] = 35u;
    ether_header->d_addr.addr_bytes[2ul] = 69u;
    ether_header->d_addr.addr_bytes[3ul] = 103u;
    ether_header->d_addr.addr_bytes[4ul] = 137u;
    ether_header->d_addr.addr_bytes[5ul] = 1u;
    ether_header->s_addr.addr_bytes[0ul] = 0u;
    ether_header->s_addr.addr_bytes[1ul] = 0u;
    ether_header->s_addr.addr_bytes[2ul] = 0u;
    ether_header->s_addr.addr_bytes[3ul] = 0u;
    ether_header->s_addr.addr_bytes[4ul] = 0u;
    ether_header->s_addr.addr_bytes[5ul] = 0u;
    return 1;
  }  // !device
}

void init_retas() {
  for (unsigned i = 0; i < MAX_NUM_DEVICES; i++) {
    retas_per_device[i].set = false;
  }
}
