#include "util.h"
#include <string.h>
#include <stdlib.h>

// Stack manipulation

bool synapse_get_stack_from_environment(env_ptr_t env, stack_ptr_t *stack,
                                        size_t expected_stack_size) {
  return NULL != env &&
         NULL != (*stack = synapse_runtime_environment_stack(env)) &&
         expected_stack_size == synapse_runtime_wrappers_stack_size(*stack);
}

bool synapse_extract_from_stack(stack_ptr_t stack, string_ptr_t *payload,
                                pair_ptr_t **meta, size_t **meta_size) {
  return NULL != stack &&
         NULL != (*payload = synapse_runtime_wrappers_stack_pop(stack)) &&
         NULL != (*meta_size = synapse_runtime_wrappers_stack_pop(stack)) &&
         NULL != (*meta = synapse_runtime_wrappers_stack_pop(stack));
}

bool synapse_get_packet_in_metadata(pair_ptr_t *meta, size_t *meta_size,
                                    string_t meta_name, string_ptr_t *result) {
  if (NULL == meta || NULL == meta_size) {
    return false;
  }

  pair_ptr_t entry;
  string_ptr_t name;

  for (size_t i = 0; i < *meta_size; i++) {
    if (NULL == (entry = meta[i]) || NULL == (name = entry->left)) {
      return false;
    }

    if (0 == strcmp(name->str, meta_name.str)) {
      return NULL != (*result = entry->right);
    }
  }

  return false;
}

pair_ptr_t *alloc_pairs(stack_ptr_t stack, size_t pairs_sz) {
  if (NULL == stack) {
    return NULL;
  }

  pair_ptr_t *pairs = NULL;
  if (NULL == (pairs = synapse_runtime_wrappers_stack_push(
                   stack, malloc(pairs_sz * sizeof(pair_ptr_t))))) {
    return NULL;
  }

  size_t *pairs_sz_dyn = NULL;
  if (NULL == (pairs_sz_dyn = synapse_runtime_wrappers_stack_push(
                   stack, malloc(sizeof(size_t))))) {
    return NULL;
  }

  *pairs_sz_dyn = pairs_sz;
  return pairs;
}

pair_ptr_t *synapse_alloc_meta(stack_ptr_t stack, size_t meta_sz) {
  return alloc_pairs(stack, meta_sz);
}

pair_ptr_t *synapse_alloc_tags(stack_ptr_t stack, size_t tags_sz) {
  return alloc_pairs(stack, tags_sz);
}

pair_ptr_t *add_pair(pair_ptr_t *pairs, void *left, void *right) {
  return (NULL == pairs ||
          NULL == (*pairs++ = synapse_runtime_wrappers_pair_new(left, right)))
             ? NULL
             : pairs;
}

pair_ptr_t *synapse_add_meta(pair_ptr_t *meta, string_t name, string_t value) {
  return add_pair(meta, synapse_runtime_wrappers_string_new(name.str, name.sz),
                  synapse_runtime_wrappers_string_new(value.str, value.sz));
}

pair_ptr_t *synapse_add_tag(pair_ptr_t *tags, string_t name, uint32_t value) {
  return add_pair(tags, synapse_runtime_wrappers_string_new(name.str, name.sz),
                  synapse_runtime_wrappers_p4_uint32_new(value));
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
