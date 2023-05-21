#pragma once

#include <stdint.h>

#include <rte_ether.h>

struct nf_config {
  // "Main" LAN (i.e. internal) device
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;

  // External IP address
  uint32_t external_addr;

  // Size of the flow table
  uint32_t max_flows;
};
