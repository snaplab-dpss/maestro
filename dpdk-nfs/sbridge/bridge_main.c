#ifdef KLEE_VERIFICATION
#include "lib/models/verified/map-control.h"  //for map_reset
#endif                                        // KLEE_VERIFICATION
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_ethdev.h>

#include "lib/verified/double-chain.h"
#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/expirator.h"
#include "lib/verified/ether.h"

#include "nf.h"
#include "nf-util.h"
#include "nf-log.h"
#include "nf-parse.h"
#include "bridge_config.h"
#include "state.h"

struct nf_config config;

struct State *mac_tables;

int bridge_get_device(struct rte_ether_addr *dst, uint16_t src_device) {
  int device = -1;
  struct StaticKey k;
  memcpy(&k.addr, dst, sizeof(struct rte_ether_addr));
  k.device = src_device;
  int present = map_get(mac_tables->st_map, &k, &device);
  if (present) {
    return device;
  }
  return -1;
}

// File parsing, is not really the kind of code we want to verify.
#ifdef KLEE_VERIFICATION
void read_static_ft_from_file(struct Map *stat_map, struct Vector *stat_keys,
                              uint32_t stat_capacity) {}

static void read_static_ft_from_array(struct Map *stat_map,
                                      struct Vector *stat_keys,
                                      uint32_t stat_capacity) {}

#else  // KLEE_VERIFICATION

#ifndef NFOS
static void read_static_ft_from_file(struct Map *stat_map,
                                     struct Vector *stat_keys,
                                     uint32_t stat_capacity) {
  if (config.static_config_fname[0] == '\0') {
    // No static config
    return;
  }

  FILE *cfg_file = fopen(config.static_config_fname, "r");
  if (cfg_file == NULL) {
    rte_exit(EXIT_FAILURE, "Error opening the static config file: %s",
             config.static_config_fname);
  }

  unsigned number_of_lines = 0;
  char ch;
  do {
    ch = fgetc(cfg_file);
    if (ch == '\n') number_of_lines++;
  } while (ch != EOF);

  // Make sure the hash table is occupied only by 50%
  unsigned capacity = number_of_lines * 2;
  rewind(cfg_file);
  if (stat_capacity <= capacity) {
    rte_exit(EXIT_FAILURE, "Too many static rules (%d), max: %d",
             number_of_lines, stat_capacity / 2);
  }
  int count = 0;

  while (1) {
    char mac_addr_str[20];
    char source_str[10];
    char target_str[10];
    int result = fscanf(cfg_file, "%18s", mac_addr_str);
    if (result != 1) {
      if (result == EOF)
        break;
      else {
        NF_INFO("Cannot read MAC address from file: %s", strerror(errno));
        goto finally;
      }
    }

    result = fscanf(cfg_file, "%9s", source_str);
    if (result != 1) {
      if (result == EOF) {
        NF_INFO("Incomplete config string: %s, skip", mac_addr_str);
        break;
      } else {
        NF_INFO("Cannot read the filtering target for MAC %s: %s", mac_addr_str,
                strerror(errno));
        goto finally;
      }
    }

    result = fscanf(cfg_file, "%9s", target_str);
    if (result != 1) {
      if (result == EOF) {
        NF_INFO("Incomplete config string: %s, skip", mac_addr_str);
        break;
      } else {
        NF_INFO("Cannot read the filtering target for MAC %s: %s", mac_addr_str,
                strerror(errno));
        goto finally;
      }
    }

    int device_from;
    int device_to;
    char *temp;
    struct StaticKey *key = 0;
    vector_borrow(stat_keys, count, (void **)&key);

    // Ouff... the strings are extracted, now let's parse them.
    result = nf_parse_etheraddr(mac_addr_str, &key->addr);
    if (result < 0) {
      NF_INFO("Invalid MAC address: %s, skip", mac_addr_str);
      continue;
    }

    device_from = strtol(source_str, &temp, 10);
    if (temp == source_str || *temp != '\0') {
      NF_INFO("Non-integer value for the forwarding rule: %s (%s), skip",
              mac_addr_str, target_str);
      continue;
    }

    device_to = strtol(target_str, &temp, 10);
    if (temp == target_str || *temp != '\0') {
      NF_INFO("Non-integer value for the forwarding rule: %s (%s), skip",
              mac_addr_str, target_str);
      continue;
    }

    // Now everything is alright, we can add the entry
    key->device = device_from;
    map_put(stat_map, &key->addr, device_to);
    vector_return(stat_keys, count, key);
    ++count;
    assert(count < capacity);
  }
finally:
  fclose(cfg_file);
}
#endif  // NFOS

struct {
  const char mac_addr[18];
  const int device_from;
  const int device_to;
} static_rules[] = {
    {"00:00:00:00:00:00", 0, 0},
};

static void read_static_ft_from_array(struct Map *stat_map,
                                      struct Vector *stat_keys,
                                      uint32_t stat_capacity) {
  unsigned number_of_entries = sizeof(static_rules) / sizeof(static_rules[0]);

  // Make sure the hash table is occupied only by 50%
  unsigned capacity = number_of_entries * 2;
  if (stat_capacity <= capacity) {
    rte_exit(EXIT_FAILURE, "Too many static rules (%d), max: %d",
             number_of_entries, CAPACITY_UPPER_LIMIT / 2);
  }
  int count = 0;

  for (int idx = 0; idx < number_of_entries; idx++) {
    struct StaticKey *key = 0;
    vector_borrow(stat_keys, count, (void **)&key);

    int result = nf_parse_etheraddr(static_rules[idx].mac_addr, &key->addr);
    if (result < 0) {
      NF_INFO("Invalid MAC address: %s, skip", static_rules[idx].mac_addr);
      continue;
    }

    // Now everything is alright, we can add the entry
    key->device = static_rules[idx].device_from;
    map_put(stat_map, &key->addr, static_rules[idx].device_to);
    vector_return(stat_keys, count, key);
    ++count;
    assert(count < capacity);
  }
}

#endif  // KLEE_VERIFICATION

bool nf_init(void) {
  unsigned stat_capacity = 8192;  // Has to be power of 2
  unsigned capacity = config.dyn_capacity;
  assert(stat_capacity < CAPACITY_UPPER_LIMIT - 1);

  mac_tables = alloc_state(capacity, stat_capacity, rte_eth_dev_count_avail());
  if (mac_tables == NULL) {
    return false;
  }
#ifdef NFOS
  read_static_ft_from_array(mac_tables->st_map, mac_tables->st_vec,
                            stat_capacity);
#else
  read_static_ft_from_file(mac_tables->st_map, mac_tables->st_vec,
                           stat_capacity);
#endif
  return true;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);

  int forward_to = bridge_get_device(&rte_ether_header->d_addr, device);

  if (forward_to == -1) {
    return FLOOD_FRAME;
  }

  if (forward_to == -2) {
    NF_DEBUG("filtered frame");
    return device;
  }

  return forward_to;
}
