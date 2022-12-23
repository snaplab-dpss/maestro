#pragma once

#include <stdint.h>

#include <rte_ether.h>

struct nf_config {
  // "Main" LAN (i.e. internal) device, used for no-op not for NAT
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;
};
