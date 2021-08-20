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

#define SYNAPSE_MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// Runtime configuration

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

void synapse_runtime_config_clear(synapse_config_t *config) {
  config->devices = NULL;
  config->devices_sz = 0;
  config->tags_names = NULL;
  config->tags_sz = 0;
  config->tags = NULL;
  config->tags_updated = false;
}

void synapse_runtime_config_print(synapse_config_t *config) {
  puts(":: Configuration summary ::\n");

  printf("Devices (%lu):\t", config->devices_sz);
  for (size_t i = 0; i < config->devices_sz; i++) {
    printf("%" SCNu32 "%s", config->devices[i],
           i < config->devices_sz - 1 ? ", " : "");
  }
  puts("");

  if (config->tags_sz > 0) {
    SYNAPSE_LOOP_START_TAGS(config->tags_sz)
    print_tag(config->tags_names[i], config->tags[i]);
    LOOP_END;
  }
}

void synapse_runtime_pkt_in_clear(synapse_pkt_in_t *pkt_in) {
  pkt_in->meta = NULL;
  pkt_in->meta_sz = 0;
  pkt_in->payload = NULL;
}

uint32_t *
synapse_runtime_config_get_tag_by_table_name(synapse_config_t *config,
                                             string_t table_name,
                                             string_ptr_t *field_match_name) {
  size_t alias_sz = table_name.sz - 16;
  size_t field_sz = alias_sz + 5 /* meta. */ + 4 /* _tag */;

  char buffer[field_sz];
  strncpy(buffer, "meta.", 5);
  strncpy(buffer + 5, table_name.str + 16, alias_sz);
  strncpy(buffer + 5 + alias_sz, "_tag", 4);

  if (NULL == (*field_match_name =
                   synapse_runtime_wrappers_string_new(buffer, field_sz))) {
    return NULL;
  }

  // Search the tag
  string_t tag_name = { .str = buffer + 5, .sz = field_sz - 5 };
  string_t tag_name_cmp;

  for (size_t i = 0; i < config->tags_sz; i++) {
    tag_name_cmp = config->tags_names[i];

    if (0 == strncmp(tag_name_cmp.str, tag_name.str,
                     SYNAPSE_MIN(tag_name_cmp.sz, tag_name.sz))) {
      return &config->tags[i];
    }
  }

  return NULL;
}

void synapse_runtime_pkt_in_print(synapse_pkt_in_t *pkt_in) {
  puts(":: Packet-in summary ::\n");

  if (NULL != pkt_in->payload) {
    printf("Payload (%lu B):\t\"", pkt_in->payload->sz);
    for (size_t i = 0; i < pkt_in->payload->sz; i++) {
      printf("\\0%02x", pkt_in->payload->str[i]);
    }
    puts("\"");
  }

  if (pkt_in->meta_sz > 0) {
    SYNAPSE_LOOP_START_META(pkt_in->meta_sz)
    print_meta_entry(pkt_in->meta[i]);
    LOOP_END;
  }
}

void synapse_runtime_pkt_out_clear(synapse_pkt_out_t *pkt_out) {
  pkt_out->payload = NULL;

  pkt_out->meta = NULL;
  pkt_out->meta_sz = 0;

  pkt_out->tags = NULL;
  pkt_out->tags_sz = 0;
}

void synapse_runtime_pkt_out_print(synapse_pkt_out_t *pkt_out) {
  puts(":: Packet-out summary ::\n");

  if (NULL != pkt_out->payload) {
    printf("Payload (%lu B):\t\"", pkt_out->payload->sz);
    for (size_t i = 0; i < pkt_out->payload->sz; i++) {
      printf("\\0%02x", pkt_out->payload->str[i]);
    }
    puts("\"");
  }

  if (pkt_out->meta_sz > 0) {
    SYNAPSE_LOOP_START_META(pkt_out->meta_sz)
    print_meta_entry(pkt_out->meta[i]);
    LOOP_END;
  }

  if (pkt_out->tags_sz > 0) {
    SYNAPSE_LOOP_START_TAGS(pkt_out->tags_sz)
    print_tag_entry(pkt_out->tags[i]);
    LOOP_END;
  }
}

// Environment manipulation

bool synapse_get_helper_from_environment(env_ptr_t env, helper_ptr_t *helper) {
  return NULL != helper && NULL != (*helper = env->helper);
}

bool synapse_get_queue_from_environment(env_ptr_t env,
                                        update_queue_ptr_t *queue) {
  return NULL != env && NULL != (*queue = env->queue);
}

bool synapse_get_stack_from_environment(env_ptr_t env, stack_ptr_t *stack,
                                        size_t expected_stack_sz) {
  return NULL != env && NULL != (*stack = env->stack) &&
         expected_stack_sz == synapse_runtime_wrappers_stack_size(*stack);
}

// Stack manipulation

bool synapse_populate_pkt_in_from_stack(stack_ptr_t stack,
                                        synapse_pkt_in_t *pkt_in) {
  if (NULL == stack) {
    return false;
  }

  if (NULL == (pkt_in->payload = synapse_runtime_wrappers_stack_pop(stack))) {
    return false;
  }

  pkt_in->meta_sz = *(size_t *)synapse_runtime_wrappers_stack_pop(stack);

  if (NULL == (pkt_in->meta = synapse_runtime_wrappers_stack_pop(stack))) {
    return false;
  }

  return true;
}

bool synapse_get_pkt_in_metadata(synapse_pkt_in_t *pkt_in, string_t meta_name,
                                 string_ptr_t *result) {
  if (NULL == pkt_in) {
    return false;
  }

  pair_ptr_t entry;
  string_ptr_t name;

  for (size_t i = 0; i < pkt_in->meta_sz && NULL != (entry = pkt_in->meta[i]) &&
                     NULL != (name = entry->left);
       i++) {
    if (0 == strcmp(name->str, meta_name.str)) {
      return NULL != (*result = entry->right);
    }
  }

  return false;
}

bool synapse_pkt_out_set_payload(synapse_pkt_out_t *pkt_out,
                                 string_ptr_t payload) {
  return NULL != pkt_out && NULL != (pkt_out->payload = payload);
}

bool synapse_pkt_out_set_meta(synapse_pkt_out_t *pkt_out, string_t name,
                              string_t value) {
  if (NULL == pkt_out ||
      NULL == (pkt_out->meta = realloc(pkt_out->meta, pkt_out->meta_sz + 1))) {

    SYNAPSE_ERROR("Could not allocate space for more metadata");
    return false;
  }

  return NULL !=
         (pkt_out->meta[pkt_out->meta_sz++] = synapse_runtime_wrappers_pair_new(
              synapse_runtime_wrappers_string_new(name.str, name.sz),
              synapse_runtime_wrappers_string_new(value.str, value.sz)));
}

bool synapse_pkt_out_set_tag(synapse_pkt_out_t *pkt_out, string_t name,
                             uint32_t value) {
  if (NULL == pkt_out ||
      NULL == (pkt_out->tags = realloc(pkt_out->tags, pkt_out->tags_sz + 1))) {
    SYNAPSE_ERROR("Could not allocate space for more tags");
    return false;
  }

  return NULL !=
         (pkt_out->tags[pkt_out->tags_sz++] = synapse_runtime_wrappers_pair_new(
              synapse_runtime_wrappers_string_new(name.str, name.sz),
              synapse_runtime_wrappers_p4_uint32_new(value)));
}

bool synapse_pkt_out_flush(env_ptr_t env, synapse_pkt_out_t *pkt_out) {
  stack_ptr_t stack;
  if (!synapse_get_stack_from_environment(env, &stack, 0)) {
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

  synapse_runtime_wrappers_stack_push(stack, pkt_out->meta);
  *meta_sz = pkt_out->meta_sz;
  synapse_runtime_wrappers_stack_push(stack, meta_sz);

  synapse_runtime_wrappers_stack_push(stack, pkt_out->payload);

  synapse_runtime_wrappers_stack_push(stack, pkt_out->tags);
  *tags_sz = pkt_out->tags_sz;
  synapse_runtime_wrappers_stack_push(stack, tags_sz);

  synapse_runtime_pkt_out_clear(pkt_out);
  return true;
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

// Helpers

bool synapse_queue_update(env_ptr_t env, p4_update_ptr_t update) {
  update_queue_ptr_t queue = NULL;
  if (!synapse_get_queue_from_environment(env, &queue)) {
    return false;
  }

  return synapse_runtime_update_queue_queue(queue, update);
}

bool synapse_queue_configure_multicast_group(env_ptr_t env,
                                             synapse_config_t *config) {
  if (0 == config->devices_sz) {
    return true;
  }

  helper_ptr_t helper = NULL;
  if (!synapse_get_helper_from_environment(env, &helper)) {
    return false;
  }

  p4_replica_ptr_t *replicas;
  if ((0 != config->devices_sz && NULL == config->devices) ||
      (NULL ==
       (replicas = malloc(config->devices_sz * sizeof(p4_replica_ptr_t))))) {
    return false;
  }

  size_t counter = 0;
  for (size_t i = 0; i < config->devices_sz; i++) {
    if (NULL == (replicas[i] = synapse_runtime_p4_replica_new(
                     helper, config->devices[i], ++counter))) {
      return false;
    }
  }

  return synapse_queue_update(
      env, synapse_runtime_p4_update_new(
               helper, Update_Insert,
               synapse_runtime_p4_entity_new(
                   helper, Entity_PacketReplicationEngineEntry,
                   synapse_runtime_p4_packet_replication_engine_entry_new(
                       helper, synapse_runtime_p4_multicast_group_entry_new(
                                   helper, SYNAPSE_MCAST_GROUP_ID, replicas,
                                   config->devices_sz)))));
}

bool synapse_queue_insert_table_entry_match_tag(synapse_config_t *config,
                                                string_t table_name,
                                                helper_ptr_t helper,
                                                p4_info_table_ptr_t table_info,
                                                p4_field_match_ptr_t *match) {

  return true;
}

bool synapse_queue_insert_table_entry(env_ptr_t env, synapse_config_t *config,
                                      string_t table_name, pair_t *key,
                                      size_t key_sz, string_t action_name,
                                      pair_t *action_params,
                                      size_t action_params_sz, int32_t priority,
                                      uint64_t idle_timeout_ns) {
  helper_ptr_t helper;
  update_queue_ptr_t queue;
  if (!synapse_get_helper_from_environment(env, &helper) ||
      !synapse_get_queue_from_environment(env, &queue)) {
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
      return false;
    }

    uint32_t *tag = NULL;
    string_ptr_t tag_match = NULL;
    if (NULL == (tag = synapse_runtime_config_get_tag_by_table_name(
                     config, table_name, &tag_match))) {
      SYNAPSE_ERROR("Could not locate tag");
      return false;
    }

    p4_info_match_field_ptr_t tag_match_info =
        synapse_runtime_p4_info_match_field_new(helper, table_info, tag_match);
    uint32_t tag_match_field_id =
        synapse_runtime_p4_info_match_field_id(tag_match_info);

    string_ptr_t range_low = synapse_encode_p4_uint32(++*tag);
    config->tags_updated = true;
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

bool synapse_queue_modify_table_entry(env_ptr_t env) { return false; }

bool synapse_queue_delete_table_entry(env_ptr_t env) { return false; }

/**
 * table name (string_t)
 * key (pair<string_t, string_t>)
 * action name (string_t)
 * action params (pair<string_t, string_t>)
 */