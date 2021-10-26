#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#define SYNAPSE_LOOP_START_META(sz)                                            \
  printf("Metadata (%lu):\n", sz);                                             \
  for (size_t i = 0; i < sz; i++) {

#define SYNAPSE_LOOP_START_TAGS(sz)                                            \
  printf("Tags (%lu):\n", sz);                                                 \
  for (size_t i = 0; i < sz; i++) {

#define LOOP_END                                                               \
  }                                                                            \
  puts("")

// Debuggers

void print_meta(string_ptr_t name, string_ptr_t value) {
  printf("<%.*s, \"", (int)name->sz, name->str);
  for (size_t i = 0; i < value->sz; i++) {
    printf("\\0%02x", value->str[i]);
  }
  printf("\">\n");
}

void print_tag(string_t name, uint32_t value) {
  printf("<%.*s, %d>\n", (int)name.sz, name.str, value);
}

void print_meta_entry(pair_ptr_t entry) {
  print_meta(entry->left, entry->right);
}

void print_tag_entry(pair_ptr_t entry) {
  print_tag(*((string_ptr_t)entry->left),
            ((p4_uint32_ptr_t)entry->right)->value);
}

// Runtime configuration

// FIXME Replace `void **` with `struct ? **`
bool synapse_runtime_config_get_libvig_objs_by_table_name(string_t table_name,
                                                          void **vector,
                                                          void **dchain,
                                                          void **map) {
  for (size_t i = 0; i < synapse_config.bmv2_tables_sz; i++) {
    synapse_bmv2_table_t table = synapse_config.bmv2_tables[i];

    if (synapse_runtime_wrappers_string_equals(&table_name, &(table.name))) {
      for (size_t i = 0; i < table.libvig_objs_sz; i++) {
        switch (table.libvig_objs[i].type) {
          case LIBVIG_VECTOR: {
            *vector = (struct Vector *)table.libvig_objs[i].ptr;
          } break;

          case LIBVIG_DCHAIN: {
            *dchain = (struct DoubleChain *)table.libvig_objs[i].ptr;
          } break;

          case LIBVIG_MAP: {
            *map = (struct Map *)table.libvig_objs[i].ptr;
          } break;

          default:
            SYNAPSE_ERROR("Unknown libvig object");
            return false;
        }
      }

      return true;
    }
  }

  return false;
}

bool synapse_runtime_config_get_tag_by_table_name(
    string_t table_name, uint32_t **tag, string_ptr_t *field_match_name) {
  size_t alias_sz = table_name.sz - 16; // Remove prefix `SyNAPSE_Ingress.`
  size_t field_sz = alias_sz + 5 /* meta. */ + 4 /* _tag */;

  char buffer[field_sz];
  strncpy(buffer, "meta.", 5);
  strncpy(buffer + 5, table_name.str + 16, alias_sz);
  strncpy(buffer + 5 + alias_sz, "_tag", 4);
  *field_match_name = synapse_runtime_wrappers_string_new(buffer, field_sz);

  for (size_t i = 0; i < synapse_config.bmv2_tables_sz; i++) {
    if (synapse_runtime_wrappers_string_equals(
            &table_name, &(synapse_config.bmv2_tables[i].name))) {
      *tag = &(synapse_config.bmv2_tables[i].tag);
      return true;
    }
  }

  return false;
}

void synapse_runtime_config_print(synapse_config_t *config) {
  puts(":: Configuration summary ::\n");

  printf("Devices (%lu):\t", synapse_config.devices_sz);
  for (size_t i = 0; i < synapse_config.devices_sz; i++) {
    printf("%" SCNu32 "%s", synapse_config.devices[i],
           i < synapse_config.devices_sz - 1 ? ", " : "");
  }
  puts("");

  printf("BMv2 tables (%lu):\n", synapse_config.bmv2_tables_sz);
}

void synapse_runtime_config_reset(synapse_config_t *config) {
  synapse_config.devices = NULL;
  synapse_config.devices_sz = 0;

  synapse_config.bmv2_tables = NULL;
  synapse_config.bmv2_tables_sz = 0;
  synapse_config.bmv2_tables_modified = false;
}

// Runtime packet-in

void synapse_runtime_pkt_in_print() {
  puts(":: Packet-in summary ::\n");

  if (NULL != synapse_pkt_in.payload) {
    printf("Payload (%lu B):\t\"", synapse_pkt_in.payload->sz);
    for (size_t i = 0; i < synapse_pkt_in.payload->sz; i++) {
      printf("\\0%02x", synapse_pkt_in.payload->str[i]);
    }
    puts("\"");
  }

  if (synapse_pkt_in.meta_sz > 0) {
    SYNAPSE_LOOP_START_META(synapse_pkt_in.meta_sz)
    print_meta_entry(synapse_pkt_in.meta[i]);
    LOOP_END;
  }
}

void synapse_runtime_pkt_in_reset() {
  synapse_pkt_in.meta = NULL;
  synapse_pkt_in.meta_sz = 0;

  synapse_pkt_in.payload = NULL;
}

bool synapse_runtime_pkt_in_get_meta_by_name(string_t meta_name,
                                             string_ptr_t *result) {
  pair_ptr_t entry = NULL;
  string_ptr_t name = NULL;

  for (size_t i = 0;
       i < synapse_pkt_in.meta_sz && NULL != (entry = synapse_pkt_in.meta[i]) &&
       NULL != (name = entry->left);
       i++) {
    if (0 == strcmp(name->str, meta_name.str)) {
      return NULL != (*result = entry->right);
    }
  }

  return false;
}

bool synapse_runtime_pkt_in_populate_from_stack(stack_ptr_t stack) {
  if (NULL == stack) {
    return false;
  }

  if (NULL == (synapse_pkt_in.payload =
                   (string_ptr_t)synapse_runtime_wrappers_stack_pop(stack))) {
    return false;
  }

  synapse_pkt_in.meta_sz = *(size_t *)synapse_runtime_wrappers_stack_pop(stack);

  if (NULL == (synapse_pkt_in.meta =
                   (pair_ptr_t *)synapse_runtime_wrappers_stack_pop(stack))) {
    return false;
  }

  return true;
}

// Runtime packet-out

void synapse_runtime_pkt_out_print() {
  puts(":: Packet-out summary ::\n");

  if (NULL != synapse_pkt_out.payload) {
    printf("Payload (%lu B):\t\"", synapse_pkt_out.payload->sz);
    for (size_t i = 0; i < synapse_pkt_out.payload->sz; i++) {
      printf("\\0%02x", synapse_pkt_out.payload->str[i]);
    }
    puts("\"");
  }

  if (synapse_pkt_out.meta_sz > 0) {
    SYNAPSE_LOOP_START_META(synapse_pkt_out.meta_sz)
    print_meta_entry(synapse_pkt_out.meta[i]);
    LOOP_END;
  }

  if (synapse_pkt_out.tags_sz > 0) {
    SYNAPSE_LOOP_START_TAGS(synapse_pkt_out.tags_sz)
    print_tag_entry(synapse_pkt_out.tags[i]);
    LOOP_END;
  }
}

void synapse_runtime_pkt_out_reset() {
  synapse_pkt_out.payload = NULL;

  synapse_pkt_out.meta = NULL;
  synapse_pkt_out.meta_sz = 0;

  synapse_pkt_out.tags = NULL;
  synapse_pkt_out.tags_sz = 0;
}

bool synapse_runtime_pkt_out_set_meta(string_t name, string_t value) {
  SYNAPSE_DEBUG("Setting out meta `%.*s` to `%.*s`", (int)name.sz, name.str,
                (int)value.sz, value.str);

  if (NULL == (synapse_pkt_out.meta = realloc(synapse_pkt_out.meta,
                                              synapse_pkt_out.meta_sz + 1))) {

    SYNAPSE_ERROR("Could not allocate space for more metadata");
    return false;
  }

  return NULL !=
         (synapse_pkt_out.meta[synapse_pkt_out.meta_sz++] =
              synapse_runtime_wrappers_pair_new(
                  synapse_runtime_wrappers_string_new(name.str, name.sz),
                  synapse_runtime_wrappers_string_new(value.str, value.sz)));
}

bool synapse_runtime_pkt_out_set_payload(string_ptr_t payload) {
  return NULL != (synapse_pkt_out.payload = payload);
}

bool synapse_runtime_pkt_out_set_tag(string_t table_name, uint32_t value) {
  SYNAPSE_DEBUG("Setting out tag `%.*s` to `%" SCNu32 "`", (int)table_name.sz,
                table_name.str, value);

  if (NULL == (synapse_pkt_out.tags = realloc(synapse_pkt_out.tags,
                                              synapse_pkt_out.tags_sz + 1))) {
    SYNAPSE_ERROR("Could not allocate space for more tags");
    return false;
  }

  size_t alias_sz = table_name.sz - 16; // Remove prefix `SyNAPSE_Ingress.`
  size_t tag_sz = alias_sz + 4 /* _tag */;

  char buffer[tag_sz];
  strncpy(buffer, table_name.str + 16, alias_sz);
  strncpy(buffer + alias_sz, "_tag", 4);

  return NULL != (synapse_pkt_out.tags[synapse_pkt_out.tags_sz++] =
                      synapse_runtime_wrappers_pair_new(
                          synapse_runtime_wrappers_string_new(buffer, tag_sz),
                          synapse_runtime_wrappers_p4_uint32_new(value)));
}

bool synapse_runtime_pkt_out_update_tags_if_needed() {
  if (synapse_config.bmv2_tables_modified) {
    for (size_t i = 0; i < synapse_config.bmv2_tables_sz; i++) {
      if (!synapse_runtime_pkt_out_set_tag(synapse_config.bmv2_tables[i].name,
                                           synapse_config.bmv2_tables[i].tag)) {
        SYNAPSE_ERROR("Could not set tag");
        return false;
      }
    }
  }

  return !(synapse_config.bmv2_tables_modified = false);
}

// Environment manipulation

bool synapse_environment_flush_pkt_out() {
  stack_ptr_t stack;
  if (!synapse_environment_get_stack(&stack, 0)) {
    SYNAPSE_ERROR("The environment is corrupted");
    return false;
  }

  /**
   * tags size
   * tags
   * payload
   * meta size
   * meta
   */

  size_t *meta_sz, *tags_sz;
  if (NULL == (meta_sz = malloc(sizeof(size_t))) ||
      NULL == (tags_sz = malloc(sizeof(size_t)))) {
    SYNAPSE_ERROR("Failed to allocate space for meta and tags");
    return false;
  }

  synapse_runtime_wrappers_stack_push(stack, synapse_pkt_out.meta);
  *meta_sz = synapse_pkt_out.meta_sz;
  synapse_runtime_wrappers_stack_push(stack, meta_sz);

  synapse_runtime_wrappers_stack_push(stack, synapse_pkt_out.payload);

  synapse_runtime_wrappers_stack_push(stack, synapse_pkt_out.tags);
  *tags_sz = synapse_pkt_out.tags_sz;
  synapse_runtime_wrappers_stack_push(stack, tags_sz);

  synapse_runtime_pkt_out_reset();
  return true;
}

bool synapse_environment_get_helper(helper_ptr_t *helper) {
  return NULL != helper && NULL != (*helper = synapse_env->helper);
}

bool synapse_environment_get_stack(stack_ptr_t *stack,
                                   size_t expected_stack_sz) {
  return NULL != synapse_env && NULL != (*stack = synapse_env->stack) &&
         expected_stack_sz == synapse_runtime_wrappers_stack_size(*stack);
}

bool synapse_environment_get_queue(update_queue_ptr_t *queue) {
  return NULL != synapse_env && NULL != (*queue = synapse_env->queue);
}

bool synapse_environment_queue_configure_multicast_group() {
  if (0 == synapse_config.devices_sz) {
    return true;
  }

  helper_ptr_t helper = NULL;
  update_queue_ptr_t queue = NULL;
  if (!synapse_environment_get_helper(&helper) ||
      !synapse_environment_get_queue(&queue)) {
    return false;
  }

  p4_replica_ptr_t *replicas;
  if ((0 != synapse_config.devices_sz && NULL == synapse_config.devices) ||
      (NULL == (replicas = malloc(synapse_config.devices_sz *
                                  sizeof(p4_replica_ptr_t))))) {
    return false;
  }

  size_t counter = 0;
  for (size_t i = 0; i < synapse_config.devices_sz; i++) {
    if (NULL == (replicas[i] = synapse_runtime_p4_replica_new(
                     helper, synapse_config.devices[i], ++counter))) {
      return false;
    }
  }

  return synapse_runtime_update_queue_queue(
      queue, synapse_runtime_p4_update_new(
                 helper, Update_Insert,
                 synapse_runtime_p4_entity_new(
                     helper, Entity_PacketReplicationEngineEntry,
                     synapse_runtime_p4_packet_replication_engine_entry_new(
                         helper, synapse_runtime_p4_multicast_group_entry_new(
                                     helper, SYNAPSE_MCAST_GROUP_ID, replicas,
                                     synapse_config.devices_sz)))));
}

bool synapse_environment_queue_insert_table_entry(
    string_t table_name, pair_t *key, size_t key_sz, string_t action_name,
    pair_t *action_params, size_t action_params_sz, int32_t priority,
    uint64_t idle_timeout_ns) {

  helper_ptr_t helper;
  update_queue_ptr_t queue;
  if (!synapse_environment_get_helper(&helper) ||
      !synapse_environment_get_queue(&queue)) {
    return false;
  }

  p4_info_table_ptr_t table_info =
      synapse_runtime_p4_info_table_new(helper, &table_name);
  p4_info_preamble_ptr_t table_info_preamble =
      synapse_runtime_p4_info_table_preamble(table_info);
  uint32_t table_id = synapse_runtime_p4_preamble_id(table_info_preamble);

  p4_info_action_ptr_t action_info =
      synapse_runtime_p4_info_action_new(helper, &action_name);
  p4_info_preamble_ptr_t action_info_preamble =
      synapse_runtime_p4_info_action_preamble(action_info);
  uint32_t action_id = synapse_runtime_p4_preamble_id(action_info_preamble);

  p4_field_match_ptr_t *match = NULL;
  if (key_sz > 0) {
    if (NULL == (match = malloc((key_sz + 1) * sizeof(p4_field_match_ptr_t)))) {
      SYNAPSE_ERROR("Could not allocated memory for the key");
      return false;
    }

    uint32_t *tag = NULL;
    string_ptr_t tag_match = NULL;

    if (!synapse_runtime_config_get_tag_by_table_name(table_name, &tag,
                                                      &tag_match)) {
      SYNAPSE_ERROR("Could not locate tag");
      return false;
    }

    p4_info_match_field_ptr_t tag_match_info =
        synapse_runtime_p4_info_match_field_new(helper, table_info, tag_match);
    uint32_t tag_match_field_id =
        synapse_runtime_p4_info_match_field_id(tag_match_info);

    string_ptr_t range_low = synapse_encode_p4_uint32(++*tag);
    string_ptr_t range_high = synapse_encode_p4_uint32(UINT32_MAX);

    p4_field_match_range_ptr_t range =
        synapse_runtime_p4_field_match_range_new(helper, range_low, range_high);

    match[0] = synapse_runtime_p4_field_match_new(helper, tag_match_field_id,
                                                  FieldMatch_Range, range);

    for (size_t i = 1; i < key_sz + 1; i++) {
      pair_t entry = key[i - 1];

      p4_info_match_field_ptr_t match_info =
          synapse_runtime_p4_info_match_field_new(helper, table_info,
                                                  (string_ptr_t)entry.left);
      p4_info_match_field_match_type_t field_type =
          synapse_runtime_p4_info_match_field_type(match_info);
      uint32_t field_id = synapse_runtime_p4_info_match_field_id(match_info);

      switch (field_type) {
        case MatchField_Exact: {
          string_ptr_t value = entry.right;

          match[i] = synapse_runtime_p4_field_match_new(
              helper, field_id, FieldMatch_Exact,
              synapse_runtime_p4_field_match_exact_new(helper, value));

        } break;

        case MatchField_Range: {
          pair_ptr_t range = entry.right;

          match[i] = synapse_runtime_p4_field_match_new(
              helper, field_id, FieldMatch_Range,
              synapse_runtime_p4_field_match_range_new(helper, range->left,
                                                       range->right));

        } break;

        default:
          SYNAPSE_ERROR("Unsupported match field type");
          return false;
      }
    }
  }

  p4_action_param_ptr_t *params = NULL;
  if (action_params_sz > 0) {
    if (NULL ==
        (params = malloc(action_params_sz * sizeof(p4_action_param_ptr_t)))) {
      return false;
    }

    for (size_t i = 0; i < action_params_sz; i++) {
      pair_t entry = action_params[i];

      p4_info_action_param_ptr_t param_info =
          synapse_runtime_p4_info_action_param_new(helper, action_info,
                                                   entry.left);
      uint32_t param_id = synapse_runtime_p4_info_action_param_id(param_info);

      params[i] =
          synapse_runtime_p4_action_param_new(helper, param_id, entry.right);
    }
  }

  synapse_config.bmv2_tables_modified = true;
  return synapse_runtime_update_queue_queue(
      queue,
      synapse_runtime_p4_update_new(
          helper, Update_Insert,
          synapse_runtime_p4_entity_new(
              helper, Entity_TableEntry,
              synapse_runtime_p4_table_entry_new(
                  helper, table_id, match, key_sz + 1,
                  synapse_runtime_p4_table_action_new(
                      helper, synapse_runtime_p4_action_new(
                                  helper, action_id, params, action_params_sz)),
                  priority, idle_timeout_ns))));
}

bool synapse_environment_queue_delete_table_entry(p4_table_entry_ptr_t entry) {
  helper_ptr_t helper;
  update_queue_ptr_t queue;
  if (!synapse_environment_get_helper(helper) ||
      !synapse_environment_get_queue(queue)) {
    return false;
  }

  return synapse_runtime_update_queue_queue(
      queue,
      synapse_runtime_p4_update_new(
          helper, Update_Delete,
          synapse_runtime_p4_entity_new(helper, Entity_TableEntry, entry)));
}

// Encoders

string_ptr_t synapse_encode_mac_address(const char *value) {
  return synapse_runtime_wrappers_mac_address_new(value)->bytes;
}

string_ptr_t synapse_encode_p4_uint32(uint32_t value) {
  return synapse_runtime_wrappers_p4_uint32_new(value)->bytes;
}

string_ptr_t synapse_encode_port(uint16_t value) {
  return synapse_runtime_wrappers_port_new(value)->bytes;
}

// Decoders

string_ptr_t synapse_decode_mac_address(string_ptr_t encoded) {
  return synapse_runtime_wrappers_decode_mac_address(encoded)->address;
}

uint32_t synapse_decode_p4_uint32(string_ptr_t encoded) {
  return synapse_runtime_wrappers_decode_p4_uint32(encoded)->value;
}

uint16_t synapse_decode_port(string_ptr_t encoded) {
  return synapse_runtime_wrappers_decode_port(encoded)->port;
}