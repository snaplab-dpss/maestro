#pragma once

#include <stdint.h>

#include "nf.h"

struct nf_config {
  // LAN (i.e. internal) device
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;

  // Maximum number of concurrent sources
  uint32_t capacity;

  // Maximum allowed number of touched ports
  uint32_t max_ports;

  // Expiration time of sources in microseconds
  uint32_t expiration_time;
};
