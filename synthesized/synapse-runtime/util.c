#include "util.h"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>

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