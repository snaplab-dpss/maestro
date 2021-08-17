#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include "synapse/runtime/wrapper/p4runtime/stream/handler/environment.hpp"

#define LOOP_START_META(sz)                                                    \
  printf("Metadata (%lu):\n", sz);                                             \
  for (size_t i = 0; i < sz; i++) {

#define LOOP_START_TAGS(sz)                                                    \
  printf("Tags (%lu):\n", sz);                                                 \
  for (size_t i = 0; i < sz; i++) {

#define LOOP_END                                                               \
  }                                                                            \
  puts("")

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
    LOOP_START_TAGS(config->tags_sz)
    print_tag(config->tags_names[i], config->tags[i]);
    LOOP_END;
  }
}

void synapse_runtime_pkt_in_clear(synapse_pkt_in_t *pkt_in) {
  pkt_in->meta = NULL;
  pkt_in->meta_sz = 0;
  pkt_in->payload = NULL;
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
    LOOP_START_META(pkt_in->meta_sz)
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
    LOOP_START_META(pkt_out->meta_sz)
    print_meta_entry(pkt_out->meta[i]);
    LOOP_END;
  }

  if (pkt_out->tags_sz > 0) {
    LOOP_START_TAGS(pkt_out->tags_sz)
    print_tag_entry(pkt_out->tags[i]);
    LOOP_END;
  }
}

// Environment manipulation

bool synapse_get_helper_from_environment(env_ptr_t env, helper_ptr_t *helper) {
  return NULL != helper &&
         NULL != (*helper = synapse_runtime_environment_helper(env));
}

bool synapse_get_queue_from_environment(env_ptr_t env,
                                        update_queue_ptr_t *queue) {
  return NULL != env &&
         NULL != (*queue = synapse_runtime_environment_queue(env));
}

bool synapse_get_stack_from_environment(env_ptr_t env, stack_ptr_t *stack,
                                        size_t expected_stack_size) {
  return NULL != env &&
         NULL != (*stack = synapse_runtime_environment_stack(env)) &&
         expected_stack_size == synapse_runtime_wrappers_stack_size(*stack);
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

string_ptr_t synapse_encode_port(uint16_t value) {
  return synapse_runtime_wrappers_port_new(value)->raw;
}

// Decoders

uint32_t synapse_decode_p4_uint32(string_ptr_t encoded) {
  return synapse_runtime_wrappers_decode_p4_uint32(encoded);
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

bool synapse_queue_insert_table_entry(env_ptr_t env) { return false; }

bool synapse_queue_modify_table_entry(env_ptr_t env) { return false; }

bool synapse_queue_delete_table_entry(env_ptr_t env) { return false; }