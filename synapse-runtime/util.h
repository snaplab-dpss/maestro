#ifndef VIGOR_SYNAPSE_RUNTIME_UTIL_H_
#define VIGOR_SYNAPSE_RUNTIME_UTIL_H_

#include "synapse/runtime/p4runtime/stream/handler/custom.hpp"
#include "synapse/runtime/wrapper/p4runtime/stream/handler/environment.hpp"
#include "synapse/runtime/wrapper/connector.hpp"
#include <assert.h>

#define SYNAPSE_BROADCAST_PORT (uint16_t)511
#define SYNAPSE_DROP_PORT (uint16_t)510
#define SYNAPSE_CPU_PORT (uint16_t)509

#define SYNAPSE_GRPC_ADDR "10.0.2.5:50051"
#define SYNAPSE_ARGS_PATH "/home/user/vigor/synapse-runtime/controller/bridge"
#define SYNAPSE_P4INFO_PATH SYNAPSE_ARGS_PATH "/program.p4info.txt"
#define SYNAPSE_JSON_PATH SYNAPSE_ARGS_PATH "/program.json"

// Environment stack manipulation

bool extract_stack(env_ptr_t env, stack_ptr_t *stack, size_t expected_stack_sz);

bool extract_from_stack(stack_ptr_t stack, string_ptr_t *payload,
                        pair_ptr_t **meta, size_t **meta_size);

bool get_packet_in_metadata(pair_ptr_t *meta, size_t *meta_size,
                            string_t meta_name, string_ptr_t *result);

pair_ptr_t *alloc_meta(stack_ptr_t stack, size_t meta_sz);

pair_ptr_t *alloc_tags(stack_ptr_t stack, size_t tags_sz);

pair_ptr_t *add_meta(pair_ptr_t *meta, string_t name, string_t value);

pair_ptr_t *add_tag(pair_ptr_t *tags, string_t name, uint32_t value);

// Decoders

uint32_t decode_p4_uint32(string_ptr_t encoded);

uint16_t decode_port(string_ptr_t encoded);

#endif // VIGOR_SYNAPSE_RUNTIME_UTIL_H_
