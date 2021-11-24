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

  // List of subnets that the HHH is configured to check.
  // Bit 0 of subnets_mask corresponds to subnet /0,
  // bit 1 to subnet /1, etc.
  uint32_t subnets_mask;

  // HHH burst size in B
  uint64_t burst;

  // Size of the dynamic filtering table
  uint32_t dyn_capacity;
};
