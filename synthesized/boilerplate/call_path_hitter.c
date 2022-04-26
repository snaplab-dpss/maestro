#include <linux/limits.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>
#include <getopt.h>
#include <unistd.h>
#include <pcap/pcap.h>
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

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/tcpudp_hdr.h"
#include "libvig/verified/vigor-time.h"
#include "libvig/verified/ether.h"

#include "libvig/verified/double-chain.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/map.h"
#include "libvig/verified/expirator.h"
#include "libvig/verified/cht.h"

#include "libvig/unverified/sketch.h"
#include "libvig/unverified/expirator.h"

/**********************************************
 *
 *                  PACKET-IO
 *
 **********************************************/

size_t global_total_length;
size_t global_read_length = 0;

RTE_DEFINE_PER_LCORE(bool, write_attempt);
RTE_DEFINE_PER_LCORE(bool, write_state);

void packet_state_total_length(void *p, uint32_t *len) {
  global_total_length = *len;
}

// The main IO primitive.
void packet_borrow_next_chunk(void *p, size_t length, void **chunk) {
  *chunk = (char *)p + global_read_length;
  global_read_length += length;
}

void packet_return_chunk(void *p, void *chunk) {
  global_read_length = (uint32_t)((int8_t *)chunk - (int8_t *)p);
}

uint32_t packet_get_unread_length(void *p) {
  return global_total_length - global_read_length;
}

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

void *chunks_borrowed[MAX_N_CHUNKS];
size_t chunks_borrowed_num = 0;

// this is doing nothing here, just making compilation easier
static inline void *nf_borrow_next_chunk(void *p, size_t length) {
  assert(chunks_borrowed_num < MAX_N_CHUNKS);
  void *chunk;
  packet_borrow_next_chunk(p, length, &chunk);
  chunks_borrowed[chunks_borrowed_num] = chunk;
  chunks_borrowed_num++;
  return chunk;
}

#define CHUNK_LAYOUT_IMPL(pkt, len, fields, n_fields, nests, n_nests, tag) \
/*nothing*/

#define CHUNK_LAYOUT_N(pkt, str_name, fields, nests)           \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,      \
                    sizeof(fields) / sizeof(fields[0]), nests, \
                    sizeof(nests) / sizeof(nests[0]), #str_name);

#define CHUNK_LAYOUT(pkt, str_name, fields)               \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields, \
                    sizeof(fields) / sizeof(fields[0]), NULL, 0, #str_name);

static inline void nf_return_all_chunks(void *p) {
  while (chunks_borrowed_num != 0) {
    packet_return_chunk(p, chunks_borrowed[chunks_borrowed_num - 1]);
    chunks_borrowed_num--;
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
  struct rte_eth_conf device_conf = {0};
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

struct pkt {
  uint64_t ts;
  uint32_t pktlen;
  uint8_t *pkt;
  unsigned device;
};

int cmpfunc(const void *a, const void *b) {
  struct pkt *p1 = (struct pkt *)a;
  struct pkt *p2 = (struct pkt *)b;

  if (p1->ts > p2->ts) {
    return 1;
  }

  if (p1->ts < p2->ts) {
    return -1;
  }

  return 0;
}

struct pkts {
  struct pkt *pkts;
  unsigned n_pkts;
  unsigned reserved;
};

struct pkts pkts;

uint64_t *call_path_hit_counter_ptr;
unsigned call_path_hit_counter_sz;

void packetHandler(uint8_t *userData, const struct pcap_pkthdr *pkthdr,
                   const uint8_t *packet) {
  if (pkts.reserved <= pkts.n_pkts) {
    pkts.reserved = pkts.n_pkts + 1000;
    pkts.pkts =
        (struct pkt *)realloc(pkts.pkts, sizeof(struct pkt) * pkts.reserved);
  }

  unsigned device = *((unsigned *)userData);

  pkts.pkts[pkts.n_pkts].ts =
      ((uint64_t)pkthdr->ts.tv_sec) * 1e9 + (uint64_t)pkthdr->ts.tv_usec * 1e3;
  pkts.pkts[pkts.n_pkts].pktlen = pkthdr->len;
  pkts.pkts[pkts.n_pkts].pkt = (uint8_t *)malloc(sizeof(uint8_t) * pkthdr->len);
  memcpy(pkts.pkts[pkts.n_pkts].pkt, packet, pkthdr->len);
  pkts.pkts[pkts.n_pkts].device = device;
  pkts.n_pkts++;
}

void load_pkts(const char *pcap, unsigned device) {
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  printf("Loading packets (device=%u, pcap=%s)\n", device, pcap);

  descr = pcap_open_offline(pcap, errbuf);
  if (descr == NULL) {
    printf("pcap %s\n", pcap);
    rte_exit(EXIT_FAILURE, "pcap_open_offline() failed: %s\n", errbuf);
  }

  if (pcap_loop(descr, -1, packetHandler, (uint8_t *)&device) < 0) {
    rte_exit(EXIT_FAILURE, "pcap_loop() failed\n");
  }

  if (pkts.reserved > pkts.n_pkts) {
    pkts.pkts =
        (struct pkt *)realloc(pkts.pkts, sizeof(struct pkt) * pkts.n_pkts);
  }

  pcap_close(descr);
}

struct device_conf_t {
  uint16_t device_id;
  const char* pcap;
};

struct config_t {
  struct device_conf_t* devices_conf;
  uint16_t devices;
  uint32_t loops;
};

struct config_t config;

// Main worker method (for now used on a single thread...)
static void worker_main() {
  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  vigor_time_t last_ts = 0;
  vigor_time_t base_ts = 0;
  for (unsigned loop_it = 0; loop_it < config.loops; loop_it++) {
    for (unsigned pkti = 0; pkti < pkts.n_pkts; pkti++) {
      struct pkt pkt = pkts.pkts[pkti];
      vigor_time_t current_time = pkt.ts + base_ts;

      printf("\rProcessing packets (%02d %% | loop %d/%d) ...",
            (int)(100 * (pkti + 1) / (double)pkts.n_pkts),
            loop_it+1, config.loops);
      fflush(stdout);

      packet_state_total_length(pkt.pkt, &(pkt.pktlen));

      // ignore destination device, we don't forward anywhere
      nf_process(pkt.device, pkt.pkt, pkt.pktlen, current_time);
      nf_return_all_chunks(pkt.pkt);

      last_ts = current_time;
    }

    base_ts = last_ts;
  }

  printf("\n");
  free(pkts.pkts);

  printf("Generating report...\n");

  FILE *report = fopen("nf-cph.tsv", "w");
  fprintf(report, "#cp\thits\n");
  for (unsigned i = 0; i < call_path_hit_counter_sz; i++) {
    fprintf(report, "%u\t%lu\n", i, call_path_hit_counter_ptr[i]);
  }
  fclose(report);

  exit(0);
}

void nf_config_usage(void) {
  NF_INFO(
      "Usage:\n"
      "[DPDK EAL options] -- [<device:pcap> ...] --loops <loops>\n"
      "\n"
      "\t device: networking device to feed the pcap\n"
      "\t pcap: traffic trace to analyze\n"
      "\t loops: number of times to loop the pcap\n");
}

void nf_config_print(void) {
  NF_INFO("\n--- Config ---\n");

  for (uint16_t device = 0; device < config.devices; device++) {
    NF_INFO("device: %" PRIu16 " PCAP:%s", device, config.devices_conf[device].pcap);
  }
  NF_INFO("loops: %" PRIu32, config.loops);

  NF_INFO("\n--- --- ------ ---\n");
}

#define PARSE_ERROR(format, ...)          \
  nf_config_usage();                      \
  fprintf(stderr, format, ##__VA_ARGS__); \
  exit(EXIT_FAILURE);

void nf_config_init_device(uint16_t device_id) {
  for (int i = 0; i < config.devices; i++) {
    if (config.devices_conf[i].device_id == device_id) {
      PARSE_ERROR("Duplicated device: %" PRIu16 ".", device_id);
    }
  }
  
  config.devices++;
  config.devices_conf = (struct device_conf_t*) realloc(
    config.devices_conf,
    sizeof(struct device_conf_t) * config.devices);

  config.devices_conf[config.devices - 1].pcap = NULL;
  config.devices_conf[config.devices - 1].device_id = device_id;

}
void nf_config_init(int argc, char **argv) {
  config.devices = 0;
  config.loops = 1;

  struct option long_options[] = {
    {"loops", required_argument, NULL, 'l'},
    { NULL, 0, NULL, 0}};
 
  int opt;
  opterr = 0;
  while ((opt = getopt_long(argc, argv, "l:", long_options, NULL)) != EOF) {
    switch (opt) {
      case 'l': {
        config.loops = nf_util_parse_int(optarg, "loops", 10, '\0');
        break;
      }

      default:
        PARSE_ERROR("Unknown option.\n");
    }
  }

  for (int iarg = optind; iarg < argc; iarg++) {
    const char* delim = ":";
    char* token;
    
    token = strtok(argv[iarg], delim);
    if (token == NULL) {
      PARSE_ERROR("Missing \"device\" argument.\n");
    }

    uint16_t device_id = nf_util_parse_int(token, "device", 10, '\0');
    nf_config_init_device(device_id);

    token = strtok(NULL, delim);
    if (token == NULL) {
      PARSE_ERROR("Missing \"pcap\" argument.\n");
    }

    if (access(token, F_OK) != 0) {
      PARSE_ERROR("No such file \"%s\".\n", token);
    }

    config.devices_conf[config.devices - 1].pcap = token;
  }
  
  pkts.pkts = NULL;
  pkts.n_pkts = 0;
  pkts.reserved = 0;

  for (int i = 0; i < config.devices; i++) {
    load_pkts(config.devices_conf[i].pcap, config.devices_conf[i].device_id);
  }

  printf("Sorting %u packets...\n", pkts.n_pkts);
  qsort(pkts.pkts, pkts.n_pkts, sizeof(struct pkt), cmpfunc);

  uint64_t last_ts = 0;
  for (unsigned i = 0; i < pkts.n_pkts; i++) {
    struct pkt pkt = pkts.pkts[i];
    assert(pkt.ts >= last_ts);
    last_ts = pkt.ts;
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

  nf_config_init(argc, argv);
  nf_config_print();

  // Run!
  worker_main();

  return 0;
}
