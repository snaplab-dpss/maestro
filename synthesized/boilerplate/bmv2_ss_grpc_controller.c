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

#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/tcpudp_hdr.h"
#include "libvig/verified/vigor-time.h"
#include "libvig/verified/ether.h"

#include "libvig/verified/double-chain.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/map.h"
#include "libvig/verified/expirator.h"

/**********************************************
 *
 *                  PACKET-IO
 *
 **********************************************/

size_t global_total_length;
size_t global_read_length = 0;

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
 *              SYNAPSE-RUNTIME
 *
 **********************************************/

#include "synapse/runtime/p4runtime/stream/handler/custom.hpp"
#include "synapse/runtime/wrapper/p4runtime/stream/handler/environment.hpp"
#include "synapse/runtime/wrapper/connector.hpp"

#define SYNAPSE_NOT_NULL(exp) assert(NULL != (exp))

#define SYNAPSE_BROADCAST_PORT (uint16_t)511
#define SYNAPSE_DROP_PORT (uint16_t)510
#define SYNAPSE_CPU_PORT (uint16_t)509

#define SYNAPSE_GRPC_ADDR "10.0.2.5:50051"
#define SYNAPSE_ARGS_PATH "/home/fcp/Documents/vigor/synapse-runtime/controller"
#define SYNAPSE_P4INFO_PATH SYNAPSE_ARGS_PATH "/program.p4info.txt"
#define SYNAPSE_JSON_PATH SYNAPSE_ARGS_PATH "/program.json"

env_ptr_t g_env;

// Constants
#define SYNAPSE_MCAST_GROUP_ID 1
#define SYNAPSE_MCAST_GROUP_SIZE 2

#define SYNAPSE_TABLES 2
#define SYNAPSE_HOSTS 2

string_ptr_t get_packet_in_metadata_by_name(env_ptr_t env, string_t meta_name) {
  SYNAPSE_NOT_NULL(env);

  helper_ptr_t helper = synapse_runtime_environment_helper(env);
  SYNAPSE_NOT_NULL(helper);

  stack_ptr_t stack = synapse_runtime_environment_stack(env);
  SYNAPSE_NOT_NULL(helper);

  assert(2 == synapse_runtime_wrappers_stack_size(stack));
  size_t *meta_size = synapse_runtime_wrappers_stack_pop(stack);
  SYNAPSE_NOT_NULL(meta_size);
  pair_ptr_t *meta = synapse_runtime_wrappers_stack_top(stack);
  SYNAPSE_NOT_NULL(meta);

  synapse_runtime_wrappers_stack_push(stack, meta_size); // Preserve stack
  static string_t packet_in_str = { .value = "packet_in", .size = 9 };

  p4_packet_metadata_ptr_t packet_in_meta =
      synapse_runtime_p4_info_controller_packet_metadata_new(helper,
                                                             &packet_in_str);
  SYNAPSE_NOT_NULL(packet_in_meta);

  p4_info_controller_packet_metadata_metadata_ptr_t packet_in_meta_by_name =
      synapse_runtime_p4_info_controller_packet_metadata_metadata_by_name_new(
          helper, packet_in_meta, &meta_name);
  SYNAPSE_NOT_NULL(packet_in_meta_by_name);

  uint32_t meta_id =
      synapse_runtime_p4_info_controller_packet_metadata_metadata_id(
          packet_in_meta_by_name);

  for (size_t i = 0; i < *meta_size; i++) {
    if (meta_id == *((uint32_t *)meta[i]->left)) {
      return meta[i]->right;
    }
  }

  return NULL;
}

uint16_t get_packet_in_src_device(env_ptr_t env) {
  SYNAPSE_NOT_NULL(env);

  static string_t src_device_str = { .value = "src_device", .size = 10 };

  string_ptr_t device_meta =
      get_packet_in_metadata_by_name(env, src_device_str);
  SYNAPSE_NOT_NULL(device_meta);

  port_ptr_t src_port = synapse_runtime_wrappers_decode_port(device_meta);
  SYNAPSE_NOT_NULL(src_port);

  return src_port->port;
}

void append_packet_out_metadata(env_ptr_t env, pair_ptr_t *meta,
                                size_t *meta_size, string_t meta_name,
                                string_ptr_t meta_value) {
  SYNAPSE_NOT_NULL(env);
  SYNAPSE_NOT_NULL(meta);
  SYNAPSE_NOT_NULL(meta_size);

  helper_ptr_t helper = synapse_runtime_environment_helper(env);
  SYNAPSE_NOT_NULL(helper);

  static string_t packet_out_str = { .value = "packet_out", .size = 10 };

  p4_packet_metadata_ptr_t packet_out_meta =
      synapse_runtime_p4_info_controller_packet_metadata_new(helper,
                                                             &packet_out_str);
  SYNAPSE_NOT_NULL(packet_out_meta);

  p4_info_controller_packet_metadata_metadata_ptr_t packet_out_meta_by_name =
      synapse_runtime_p4_info_controller_packet_metadata_metadata_by_name_new(
          helper, packet_out_meta, &meta_name);
  SYNAPSE_NOT_NULL(packet_out_meta_by_name);

  uint32_t *meta_id = malloc(sizeof(uint32_t));
  *meta_id = synapse_runtime_p4_info_controller_packet_metadata_metadata_id(
      packet_out_meta_by_name);
  SYNAPSE_NOT_NULL(meta_id);

  pair_ptr_t meta_pair = synapse_runtime_wrappers_pair_new(meta_id, meta_value);
  SYNAPSE_NOT_NULL(meta_pair);
  meta[(*meta_size)++] = meta_pair;
}

void push_packet_out_metadata(env_ptr_t env, uint16_t src_device,
                              uint16_t dst_device) {
  SYNAPSE_NOT_NULL(env);

  stack_ptr_t stack = synapse_runtime_environment_stack(env);
  SYNAPSE_NOT_NULL(stack);

  pair_ptr_t *packet_out_meta = malloc(1 * sizeof(pair_ptr_t));
  size_t *packet_out_meta_size = malloc(sizeof(size_t));
  *packet_out_meta_size = 0;

  static string_t src_device_str = { .value = "src_device", .size = 10 };
  port_ptr_t src_port = synapse_runtime_wrappers_port_new(src_device);
  append_packet_out_metadata(env, packet_out_meta, packet_out_meta_size,
                             src_device_str, src_port->raw);

  static string_t dst_device_str = { .value = "dst_device", .size = 10 };
  port_ptr_t dst_port = synapse_runtime_wrappers_port_new(dst_device);
  append_packet_out_metadata(env, packet_out_meta, packet_out_meta_size,
                             dst_device_str, dst_port->raw);

  synapse_runtime_wrappers_stack_clear(stack);
  synapse_runtime_wrappers_stack_push(stack, packet_out_meta);
  synapse_runtime_wrappers_stack_push(stack, packet_out_meta_size);
}

bool install_multicast_group(env_ptr_t env) {
  SYNAPSE_NOT_NULL(env);

  helper_ptr_t helper = synapse_runtime_environment_helper(env);
  SYNAPSE_NOT_NULL(helper);

  p4_replica_ptr_t *replicas =
      malloc(SYNAPSE_MCAST_GROUP_SIZE * sizeof(p4_replica_ptr_t));
  SYNAPSE_NOT_NULL(replicas);

  for (size_t i = 0; i < SYNAPSE_MCAST_GROUP_SIZE; i++) {
    replicas[i] = synapse_runtime_p4_replica_new(helper, i + 1, i + 1);
  }

  p4_multicast_group_entry_ptr_t mcast_group_entry =
      synapse_runtime_p4_multicast_group_entry_new(
          helper, SYNAPSE_MCAST_GROUP_ID, replicas, SYNAPSE_MCAST_GROUP_SIZE);
  SYNAPSE_NOT_NULL(mcast_group_entry);

  p4_packet_replication_engine_entry_ptr_t pre_entry =
      synapse_runtime_p4_packet_replication_engine_entry_new(helper,
                                                             mcast_group_entry);
  SYNAPSE_NOT_NULL(pre_entry);

  p4_entity_ptr_t entity =
      synapse_runtime_p4_entity_packet_replication_engine_entry_new(helper,
                                                                    pre_entry);
  SYNAPSE_NOT_NULL(entity);

  p4_update_ptr_t update =
      synapse_runtime_p4_update_new(helper, Update_Type_INSERT, entity);
  SYNAPSE_NOT_NULL(update);

  return synapse_runtime_update_buffer_buffer(
      synapse_runtime_environment_update_buffer(env), update);
}

bool insert_table_entry(env_ptr_t env, string_ptr_t table_name,
                        pair_ptr_t *key_matches, size_t key_matches_size,
                        string_ptr_t action_name, pair_ptr_t *action_params,
                        size_t action_params_size, uint64_t idle_timeout_ns) {
  SYNAPSE_NOT_NULL(env);

  helper_ptr_t helper = synapse_runtime_environment_helper(env);
  SYNAPSE_NOT_NULL(helper);

  // Get the P4 context
  p4_info_table_ptr_t table_info =
      synapse_runtime_p4_info_table_new(helper, table_name);
  p4_info_action_ptr_t action_info =
      synapse_runtime_p4_info_action_new(helper, action_name);

  p4_field_match_ptr_t *matches =
      malloc(key_matches_size * sizeof(p4_field_match_ptr_t));
  SYNAPSE_NOT_NULL(matches);

  for (size_t i = 0; i < key_matches_size; i++) {
    pair_ptr_t key_match = key_matches[i];
    SYNAPSE_NOT_NULL(key_match);
    string_ptr_t byte_name = key_match->left;
    SYNAPSE_NOT_NULL(byte_name);
    string_ptr_t byte_val = key_match->right;
    SYNAPSE_NOT_NULL(byte_val);

    // Retrieve field ID
    uint32_t field_id = synapse_runtime_p4_info_match_field_id(
        synapse_runtime_p4_info_match_field_new(helper, table_info, byte_name));

    // Append to the key matches
    matches[i] = synapse_runtime_p4_field_match_new(
        helper, field_id,
        synapse_runtime_p4_field_match_exact_new(helper, byte_val));
  }

  p4_action_param_ptr_t *params =
      malloc(action_params_size * sizeof(p4_action_param_ptr_t));
  SYNAPSE_NOT_NULL(params);

  for (size_t i = 0; i < action_params_size; i++) {
    pair_ptr_t action_param = action_params[i];
    SYNAPSE_NOT_NULL(action_param);
    string_ptr_t param = action_param->left;
    SYNAPSE_NOT_NULL(param);
    string_ptr_t value = action_param->right;
    SYNAPSE_NOT_NULL(value);

    // Retrieve field ID
    uint32_t param_id = synapse_runtime_p4_info_action_param_id(
        synapse_runtime_p4_info_action_param_new(helper, action_info, param));

    params[i] = synapse_runtime_p4_action_param_new(helper, param_id, value);
  }

  p4_info_preamble_ptr_t table_preamble =
      synapse_runtime_p4_info_table_preamble(table_info);
  SYNAPSE_NOT_NULL(table_preamble);
  uint32_t table_preamble_id = synapse_runtime_p4_preamble_id(table_preamble);

  p4_info_preamble_ptr_t action_preamble =
      synapse_runtime_p4_info_action_preamble(action_info);
  SYNAPSE_NOT_NULL(action_preamble);
  uint32_t action_preamble_id = synapse_runtime_p4_preamble_id(action_preamble);

  p4_action_ptr_t action = synapse_runtime_p4_action_new(
      helper, action_preamble_id, params, action_params_size);
  SYNAPSE_NOT_NULL(action);

  p4_table_action_ptr_t table_action =
      synapse_runtime_p4_table_action_new(helper, action);
  SYNAPSE_NOT_NULL(table_action);

  p4_table_entry_ptr_t table_entry = synapse_runtime_p4_table_entry_new(
      helper, table_preamble_id, matches, key_matches_size, table_action,
      idle_timeout_ns);
  SYNAPSE_NOT_NULL(table_entry);

  p4_entity_ptr_t entity =
      synapse_runtime_p4_entity_table_entry_new(helper, table_entry);
  SYNAPSE_NOT_NULL(entity);

  p4_update_ptr_t update =
      synapse_runtime_p4_update_new(helper, Update_Type_INSERT, entity);
  SYNAPSE_NOT_NULL(update);

  return synapse_runtime_update_buffer_buffer(
      synapse_runtime_environment_update_buffer(env), update);
}

bool populate_tables(env_ptr_t env) {
  SYNAPSE_NOT_NULL(env);

  static string_t tables_str[] = {
    { .value = "SyNAPSE_Ingress.map_get_35", .size = 26 },
    { .value = "SyNAPSE_Ingress.map_get_53", .size = 26 }
  };

  static string_t actions_str[] = {
    { .value = "SyNAPSE_Ingress.map_get_35_populate", .size = 35 },
    { .value = "SyNAPSE_Ingress.map_get_53_populate", .size = 35 }
  };

  static string_t key_byte_strs[] = { { .value = "key_byte_0", .size = 10 },
                                      { .value = "key_byte_1", .size = 10 },
                                      { .value = "key_byte_2", .size = 10 },
                                      { .value = "key_byte_3", .size = 10 },
                                      { .value = "key_byte_4", .size = 10 },
                                      { .value = "key_byte_5", .size = 10 },
                                      { .value = "key_byte_6", .size = 10 },
                                      { .value = "key_byte_7", .size = 10 } };

  static string_t param_0_str = { .value = "param_0", .size = 7 };

  size_t table_id, host_i_id, host_j_id;
  char buffer[18];

  // Populate two tables
  for (table_id = 0; table_id < SYNAPSE_TABLES; table_id++) {
    for (host_i_id = 1; host_i_id <= SYNAPSE_HOSTS; host_i_id++) {
      // Generate the MAC address
      sprintf(buffer, "%s%1d", "00:00:00:00:00:0", (int)host_i_id);
      mac_addr_ptr_t mac = synapse_runtime_wrappers_mac_address_new(buffer);
      char *mac_ptr;

      port_ptr_t device = synapse_runtime_wrappers_port_new(host_i_id);
      char *device_ptr = (char *)device->raw->value;

      pair_ptr_t *action_params = malloc(1 * sizeof(pair_ptr_t));
      *action_params =
          synapse_runtime_wrappers_pair_new(&param_0_str, device->raw);

      for (host_j_id = 1; host_j_id <= SYNAPSE_HOSTS; host_j_id++) {
        if (host_i_id == host_j_id) {
          continue;
        }

        // The key is made up of 8 bytes
        pair_ptr_t *key_matches = malloc(8 * sizeof(pair_ptr_t));

        // Populate the most significant 6 bytes with the MAC address
        mac_ptr = (char *)mac->raw->value;

        size_t i = 6;
        while (i--) {
          key_matches[i] = synapse_runtime_wrappers_pair_new(
              &key_byte_strs[i],
              synapse_runtime_wrappers_string_new(mac_ptr++, 1));
        }

        // Populate the least significant 2 bytes with the device
        port_ptr_t device_j = synapse_runtime_wrappers_port_new(host_j_id);
        char *device_j_ptr = (char *)device_j->raw->value;

        i = 8;
        while (i-- > 6) {
          key_matches[i] = synapse_runtime_wrappers_pair_new(
              &key_byte_strs[i],
              synapse_runtime_wrappers_string_new(device_j_ptr++, 1));
        }

        if (!insert_table_entry(env, &tables_str[table_id], key_matches, 8,
                                &actions_str[table_id], action_params, 1, 0)) {
          return false;
        }
      }
    }
  }

  return true;
}

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

static inline void *nf_borrow_next_chunk(void *p, size_t length) {
  assert(chunks_borrowed_num < MAX_N_CHUNKS);
  void *chunk;
  packet_borrow_next_chunk(p, length, &chunk);
  chunks_borrowed[chunks_borrowed_num] = chunk;
  chunks_borrowed_num++;
  return chunk;
}

#define CHUNK_LAYOUT_IMPL(pkt, len, fields, n_fields, nests, n_nests, tag)     \
/*nothing*/

#define CHUNK_LAYOUT_N(pkt, str_name, fields, nests)                           \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,                      \
                    sizeof(fields) / sizeof(fields[0]), nests,                 \
                    sizeof(nests) / sizeof(nests[0]), #str_name);

#define CHUNK_LAYOUT(pkt, str_name, fields)                                    \
  CHUNK_LAYOUT_IMPL(pkt, sizeof(struct str_name), fields,                      \
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

static inline struct rte_ipv4_hdr *
nf_then_get_rte_ipv4_header(void *rte_ether_header_, void *p,
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
    CHUNK_LAYOUT_IMPL(p, 1, NULL, 0, NULL, 0, "ipv4_options");
    *ip_options = (uint8_t *)nf_borrow_next_chunk(p, ip_options_length);
  }
  return hdr;
}

static inline struct tcpudp_hdr *
nf_then_get_tcpudp_header(struct rte_ipv4_hdr *ip_header, void *p) {
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

#define FLOOD_FRAME ((uint16_t) - 1)

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
#include "libvig/models/hardware.h"
#include "libvig/models/verified/vigor-time-control.h"
#include <klee/klee.h>
#endif // KLEE_VERIFICATION

// NFOS declares its own main method
#ifdef NFOS
#define MAIN nf_main
#else // NFOS
#define MAIN main
#endif // NFOS

// Unverified support for batching, useful for performance comparisons
#ifndef VIGOR_BATCH_SIZE
#define VIGOR_BATCH_SIZE 1
#endif

// More elaborate loop shape with annotations for verification
#ifdef KLEE_VERIFICATION
#define VIGOR_LOOP_BEGIN                                                       \
  unsigned _vigor_lcore_id = 0; /* no multicore support for now */             \
  vigor_time_t _vigor_start_time = start_time();                               \
  int _vigor_loop_termination = klee_int("loop_termination");                  \
  unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();                    \
  while (klee_induce_invariants() & _vigor_loop_termination) {                 \
    nf_loop_iteration_border(_vigor_lcore_id, _vigor_start_time);              \
    vigor_time_t VIGOR_NOW = current_time();                                   \
    /* concretize the device to avoid leaking symbols into DPDK */             \
    uint16_t VIGOR_DEVICE =                                                    \
        klee_range(0, VIGOR_DEVICES_COUNT, "VIGOR_DEVICE");                    \
    concretize_devices(&VIGOR_DEVICE, VIGOR_DEVICES_COUNT);                    \
    stub_hardware_receive_packet(VIGOR_DEVICE);
#define VIGOR_LOOP_END                                                         \
  stub_hardware_reset_receive(VIGOR_DEVICE);                                   \
  nf_loop_iteration_border(_vigor_lcore_id, VIGOR_NOW);                        \
  }
#else // KLEE_VERIFICATION
#define VIGOR_LOOP_BEGIN                                                       \
  while (1) {                                                                  \
    vigor_time_t VIGOR_NOW = current_time();                                   \
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();                  \
    for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;        \
         VIGOR_DEVICE++) {
#define VIGOR_LOOP_END                                                         \
  }                                                                            \
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
  printf("Preconfiguring the switch...\n");
  return nf_init() && install_multicast_group(env) && populate_tables(env);
}

bool synapse_runtime_handle_packet_received(env_ptr_t env) {
  SYNAPSE_NOT_NULL(env);

  stack_ptr_t stack = synapse_runtime_environment_stack(env);
  SYNAPSE_NOT_NULL(stack);

  assert(3 == synapse_runtime_wrappers_stack_size(stack));

  string_ptr_t packet_payload = synapse_runtime_wrappers_stack_pop(stack);
  SYNAPSE_NOT_NULL(packet_payload);

  // Get the ingress port (aka. device) from the packet metadata
  uint16_t src_device = get_packet_in_src_device(env);
  uint8_t *buffer = (uint8_t *)packet_payload->value;
  uint16_t packet_length = packet_payload->size;
  vigor_time_t now = current_time();

  // Read the destination address
  string_ptr_t dst_mac_address =
      synapse_runtime_wrappers_decode_mac_address(buffer)->address;
  // Read the source address
  string_ptr_t src_mac_address =
      synapse_runtime_wrappers_decode_mac_address(buffer + 6)->address;

  g_env = env;
  int dst_device = nf_process(src_device, &buffer, packet_length, now, NULL);
  g_env = NULL;

  if (FLOOD_FRAME == dst_device) {
    push_packet_out_metadata(env, src_device, SYNAPSE_BROADCAST_PORT);

  } else {
    push_packet_out_metadata(env, src_device, dst_device);
  }

  synapse_runtime_wrappers_stack_push(stack, packet_payload);
  return true;
}

bool synapse_runtime_handle_idle_timeout_notification_received(env_ptr_t env) {
  printf("Received an idle timeout notification...\n");
  return true;
}

// Main worker method using the SyNAPSE Runtime
static void worker_main(void) {
  printf("Running SyNAPSE Runtime...\n");

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

  // NF-specific config
  nf_config_init(argc, argv);
  nf_config_print();

  // Run!
  worker_main();

  return 0;
}

bool nf_init(void) { return true; }

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  return -1;
}
