#pragma once

#include <stdint.h>

#include "nf.h"

struct nf_config {
  // LAN (i.e. internal) device
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;

  // Link capacity in b/s
  uint64_t link_capacity;

  // HHH threshold in %
  uint8_t threshold;

  // Minimum size mask from 1 to 32 bits
  uint8_t min_prefix;

  // Maximum size mask from min_prefix to 32 bits
  uint8_t max_prefix;

  // HHH burst size in B
  uint64_t burst;

  // Size of the dynamic filtering table
  uint32_t dyn_capacity;
};
