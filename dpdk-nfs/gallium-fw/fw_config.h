#pragma once

#include <stdint.h>

#define TABLE_FNAME_LEN 512

struct nf_config {
  // "Main" LAN (i.e. internal) device
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;

  // Proxy table capacity
  uint32_t capacity;

  // The file containing the table entries
  char table_fname[TABLE_FNAME_LEN];
};
