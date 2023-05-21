#pragma once

#include <stdint.h>

#define TABLE_FNAME_LEN 512

struct nf_config {
  // "Main" LAN (i.e. internal) device
  uint16_t lan_device;

  // WAN device, i.e. external
  uint16_t wan_device;

  // LB flows capacity
  uint32_t capacity;

  // LB backends capacity
  uint32_t max_backends;

  // The file containing backends
  char table_fname[TABLE_FNAME_LEN];
};