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

// Runtime configuration

typedef struct {
  uint32_t *devices;
  size_t devices_sz;

  string_t *tags_names;
  uint32_t *tags;
  size_t tags_sz;
  bool tags_updated;

} synapse_config_t;

typedef struct {
  string_ptr_t payload;

  pair_ptr_t *meta;
  size_t meta_sz;

} synapse_pkt_in_t;

typedef struct {
  string_ptr_t payload;

  pair_ptr_t *meta;
  size_t meta_sz;

  pair_ptr_t *tags;
  size_t tags_sz;

} synapse_pkt_out_t;

bool synapse_runtime_config(synapse_config_t *config);

void synapse_runtime_config_clear(synapse_config_t *config);

uint32_t *
synapse_runtime_config_get_tag_by_table_name(synapse_config_t *config,
                                             string_t table_name,
                                             string_ptr_t *field_match_name);

void synapse_runtime_config_print(synapse_config_t *config);

void synapse_runtime_pkt_in_clear(synapse_pkt_in_t *pkt_in);

void synapse_runtime_pkt_in_print(synapse_pkt_in_t *pkt_in);

void synapse_runtime_pkt_out_clear(synapse_pkt_out_t *pkt_out);

void synapse_runtime_pkt_out_print(synapse_pkt_out_t *pkt_out);

static synapse_config_t synapse_config;
static synapse_pkt_in_t synapse_pkt_in;
static synapse_pkt_out_t synapse_pkt_out;

// Environment manipulation

bool synapse_get_helper_from_environment(env_ptr_t env, helper_ptr_t *helper);

bool synapse_get_stack_from_environment(env_ptr_t env, stack_ptr_t *stack,
                                        size_t expected_stack_sz);

bool synapse_get_queue_from_environment(env_ptr_t env,
                                        update_queue_ptr_t *queue);

// Stack manipulation

bool synapse_populate_pkt_in_from_stack(stack_ptr_t stack,
                                        synapse_pkt_in_t *pkt_in);

bool synapse_get_pkt_in_metadata(synapse_pkt_in_t *pkt_in, string_t meta_name,
                                 string_ptr_t *result);

bool synapse_pkt_out_set_payload(synapse_pkt_out_t *pkt_out,
                                 string_ptr_t payload);

bool synapse_pkt_out_set_meta(synapse_pkt_out_t *pkt_out, string_t name,
                              string_t value);

bool synapse_pkt_out_set_tag(synapse_pkt_out_t *pkt_out, string_t name,
                             uint32_t value);

bool synapse_pkt_out_flush(env_ptr_t env, synapse_pkt_out_t *pkt_out);

// Encoders

string_ptr_t synapse_encode_mac_address(const char *value);

string_ptr_t synapse_encode_p4_uint32(uint32_t value);

string_ptr_t synapse_encode_port(uint16_t value);

// Decoders

string_ptr_t synapse_decode_mac_address(string_ptr_t encoded);

uint32_t synapse_decode_p4_uint32(string_ptr_t encoded);

uint16_t synapse_decode_port(string_ptr_t encoded);

// Helpers

bool synapse_queue_configure_multicast_group(env_ptr_t env,
                                             synapse_config_t *config);

bool synapse_queue_insert_table_entry(env_ptr_t env, synapse_config_t *config,
                                      string_t table_name, pair_t *key,
                                      size_t key_sz, string_t action_name,
                                      pair_t *action_params,
                                      size_t action_params_sz, int32_t priority,
                                      uint64_t idle_timeout_ns);

bool synapse_queue_modify_table_entry(env_ptr_t env);

bool synapse_queue_delete_table_entry(env_ptr_t env);

#endif // VIGOR_SYNAPSE_RUNTIME_UTIL_H_
