#pragma once

#include <stdint.h>

#include "nf.h"

struct nf_config {
  // LAN (i.e. internal) device
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;

  // Maximum number of flows
  uint32_t max_flows;

  // Sketch size
  uint32_t sketch_capacity;

  // Maximum allowed number of clients
  uint16_t max_clients;

  // Expiration time of flows in microseconds
  uint64_t flow_expiration_time;

  // Expiration time of clients in microseconds
  uint64_t client_expiration_time;
};
