#ifndef VIGOR_SYNAPSE_RUNTIME_UTIL_H_
#define VIGOR_SYNAPSE_RUNTIME_UTIL_H_

#include "synapse/runtime/p4runtime/stream/handler/environment.hpp"

#define SYNAPSE_GRPC_ADDR "10.0.2.5:50051"
#define SYNAPSE_ARGS_PATH "/home/user/vigor/synapse-runtime/controller"
#define SYNAPSE_P4INFO_PATH SYNAPSE_ARGS_PATH "/program.p4info.txt"
#define SYNAPSE_JSON_PATH SYNAPSE_ARGS_PATH "/program.json"

#define SYNAPSE_CPU_PORT (uint16_t)509
#define SYNAPSE_DROP_PORT (uint16_t)510
#define SYNAPSE_BROADCAST_PORT (uint16_t)511

#define SYNAPSE_MCAST_GROUP_ID 1

/**
 * This structure provides the runtime with valuable information:
 * - network topology (i.e. the identifiers of network devices, used to
 * configure broadcasts issued by the dataplane);
 * - existing BMv2 tables (their name identifiers, tag value, and how they are
 * mapped onto one or more libvig objects).
 */

typedef enum { LIBVIG_VECTOR, LIBVIG_DCHAIN, LIBVIG_MAP } libvig_obj_type_t;

typedef struct {
  void *ptr;
  libvig_obj_type_t type;

} libvig_obj_t;

typedef struct {
  string_t name;
  uint32_t tag;

  libvig_obj_t *libvig_objs;
  size_t libvig_objs_sz;

} synapse_bmv2_table_t;

typedef struct {
  uint32_t *devices;
  size_t devices_sz;

  synapse_bmv2_table_t *bmv2_tables;
  size_t bmv2_tables_sz;
  bool bmv2_tables_modified;

} synapse_config_t;

bool synapse_runtime_config(synapse_config_t *config);

// FIXME Replace `void **` with `struct ? **`
bool synapse_runtime_config_get_libvig_objs_by_table_name(string_t table_name,
                                                          void **vector,
                                                          void **dchain,
                                                          void **map);

// Additionally, `field_match_name` is set to the appropriate key field
bool synapse_runtime_config_get_tag_by_table_name(
    string_t table_name, uint32_t **tag, string_ptr_t *field_match_name);

void synapse_runtime_config_print();

void synapse_runtime_config_reset();

/**
 * Wrapper used to represent packets arriving at the controller:
 * - payload is the string representation of the packet's payload;
 * - meta(_sz) is an array of <meta name, meta value> pairs populated by the
 * dataplane.
 */

typedef struct {
  string_ptr_t payload;

  pair_ptr_t *meta;
  size_t meta_sz;

} synapse_pkt_in_t;

void synapse_runtime_pkt_in_print();

void synapse_runtime_pkt_in_reset();

bool synapse_runtime_pkt_in_get_meta_by_name(string_t meta_name,
                                             string_ptr_t *value);

bool synapse_runtime_pkt_in_populate_from_stack(stack_ptr_t stack);

/**
 * Wrapper used to represent packets leaving the controller:
 * - payload is the string representation of the packet's payload (usually left
 * unmodified by the controller);
 * - meta(_sz) is an array of <meta name, meta value> pairs populated by the
 * controller;
 * - tags(_sz) is an array of <tag name, new tag value> populated by the
 * controller.
 */

typedef struct {
  string_ptr_t payload;

  pair_ptr_t *meta;
  size_t meta_sz;

  pair_ptr_t *tags;
  size_t tags_sz;

} synapse_pkt_out_t;

void synapse_runtime_pkt_out_print();

void synapse_runtime_pkt_out_reset();

bool synapse_runtime_pkt_out_set_meta(string_t name, string_t value);

bool synapse_runtime_pkt_out_set_payload(string_ptr_t payload);

bool synapse_runtime_pkt_out_set_tag(string_t table_name, uint32_t value);

bool synapse_runtime_pkt_out_update_tags_if_needed();

/**
 * For easy of access, and memory management purposes, keep exactly one instance
 * of each runtime structure.
 */

synapse_config_t synapse_config;
synapse_pkt_in_t synapse_pkt_in;
synapse_pkt_out_t synapse_pkt_out;
env_ptr_t synapse_env;

/**
 * These functions manipulate the handler environment either by
 * 1) retrieving elements (such as the P4 helper, the stack, or the updates
 * queue) - additional checks are sometimes performed after retrieval; OR
 * 2) updating its contents (i.e. flush elements to the environment stack).
 */

bool synapse_environment_flush_pkt_out();

bool synapse_environment_get_helper(helper_ptr_t *helper);

bool synapse_environment_get_stack(stack_ptr_t *stack,
                                   size_t expected_stack_sz);

bool synapse_environment_get_queue(update_queue_ptr_t *queue);

bool synapse_environment_queue_configure_multicast_group();

bool synapse_environment_queue_insert_table_entry(
    string_t table_name, pair_t *key, size_t key_sz, string_t action_name,
    pair_t *action_params, size_t action_params_sz, int32_t priority,
    uint64_t idle_timeout_ns);

// Encoders

string_ptr_t synapse_encode_mac_address(const char *value);

string_ptr_t synapse_encode_p4_uint32(uint32_t value);

string_ptr_t synapse_encode_port(uint16_t value);

// Decoders

string_ptr_t synapse_decode_mac_address(string_ptr_t encoded);

uint32_t synapse_decode_p4_uint32(string_ptr_t encoded);

uint16_t synapse_decode_port(string_ptr_t encoded);

#endif // VIGOR_SYNAPSE_RUNTIME_UTIL_H_
