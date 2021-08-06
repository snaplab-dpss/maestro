#ifndef VIGOR_SYNAPSE_RUNTIME_UTIL_H_
#define VIGOR_SYNAPSE_RUNTIME_UTIL_H_

#include "synapse/runtime/p4runtime/stream/handler/custom.hpp"
#include "synapse/runtime/wrapper/p4runtime/stream/handler/environment.hpp"
#include "synapse/runtime/wrapper/connector.hpp"
#include <assert.h>

#define SYNAPSE_NOT_NULL(exp) assert(NULL != (exp))

#define SYNAPSE_BROADCAST_PORT (uint16_t)511
#define SYNAPSE_DROP_PORT (uint16_t)510
#define SYNAPSE_CPU_PORT (uint16_t)509

#define SYNAPSE_GRPC_ADDR "10.0.2.5:50051"
#define SYNAPSE_ARGS_PATH "/home/user/vigor/synapse-runtime/controller"
#define SYNAPSE_P4INFO_PATH SYNAPSE_ARGS_PATH "/program.p4info.txt"
#define SYNAPSE_JSON_PATH SYNAPSE_ARGS_PATH "/program.json"

env_ptr_t g_env;

uint16_t get_packet_in_src_device(env_ptr_t env);

void push_packet_out_metadata(env_ptr_t env, uint16_t src_device,
                              uint16_t dst_device);

bool install_multicast_group(env_ptr_t env);

bool populate_tables(env_ptr_t env);

#endif // VIGOR_SYNAPSE_RUNTIME_UTIL_H_
