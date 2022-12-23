#include "psd_config.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "nf-util.h"
#include "nf-log.h"

const uint16_t DEFAULT_LAN = 1;
const uint16_t DEFAULT_WAN = 0;
const uint32_t DEFAULT_CAPACITY = 65536;
const uint32_t DEFAULT_MAX_PORTS = 60;
const uint32_t DEFAULT_EXPIRATION_TIME = 1000000;  // 1s

#define PARSE_ERROR(format, ...)          \
  nf_config_usage();                      \
  fprintf(stderr, format, ##__VA_ARGS__); \
  exit(EXIT_FAILURE);

int is_power_of_2(uint32_t d) {
  if (d == 0) return false;

  while (d != 1) {
    if (d % 2 != 0) {
      return false;
    }

    d >>= 1;
  }

  return true;
}

void nf_config_init(int argc, char **argv) {
  // Set the default values
  config.lan_device = DEFAULT_LAN;
  config.wan_device = DEFAULT_WAN;
  config.capacity = DEFAULT_CAPACITY;
  config.max_ports = DEFAULT_MAX_PORTS;
  config.expiration_time = DEFAULT_EXPIRATION_TIME;

  unsigned nb_devices = rte_eth_dev_count_avail();

  struct option long_options[] = {{"lan", required_argument, NULL, 'l'},
                                  {"wan", required_argument, NULL, 'w'},
                                  {"capacity", required_argument, NULL, 'c'},
                                  {"max-ports", required_argument, NULL, 'p'},
                                  {"expire", required_argument, NULL, 't'},
                                  {NULL, 0, NULL, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "l:w:r:t:m:M:c:", long_options,
                            NULL)) != EOF) {
    switch (opt) {
      case 'l':
        config.lan_device = nf_util_parse_int(optarg, "lan", 10, '\0');
        if (config.lan_device < 0 || config.lan_device >= nb_devices) {
          PARSE_ERROR("Invalid LAN device.\n");
        }
        break;

      case 'w':
        config.wan_device = nf_util_parse_int(optarg, "wan", 10, '\0');
        if (config.wan_device < 0 || config.wan_device >= nb_devices) {
          PARSE_ERROR("Invalid WAN device.\n");
        }
        break;

      case 'c':
        config.capacity = nf_util_parse_int(optarg, "capacity", 10, '\0');
        if (config.capacity <= 0) {
          PARSE_ERROR("Capacity must be strictly positive.\n");
        }
        if (!is_power_of_2(config.capacity)) {
          PARSE_ERROR("Capacity must be a power of 2.\n");
        }
        break;

      case 'p':
        config.max_ports = nf_util_parse_int(optarg, "max-ports", 10, '\0');
        if (config.max_ports <= 0) {
          PARSE_ERROR("Maximum number of ports must be strictly positive.\n");
        }
        if (!is_power_of_2(config.max_ports)) {
          PARSE_ERROR("Maximum number of ports must be a power of 2.\n");
        }
        break;

      case 't':
        config.expiration_time = nf_util_parse_int(optarg, "expire", 10, '\0');
        if (config.expiration_time <= 0) {
          PARSE_ERROR("Expiration time must be strictly positive.\n");
        }
        break;

      default:
        PARSE_ERROR("Unknown option %c", opt);
    }
  }

  // Reset getopt
  optind = 1;
}

void nf_config_usage(void) {
  NF_INFO(
      "Usage:\n"
      "[DPDK EAL options] --\n"
      "\t--lan <device>: LAN device,"
      " default: %" PRIu16
      ".\n"
      "\t--wan <device>: WAN device,"
      " default: %" PRIu16
      ".\n"
      "\t--capacity <capacity>: maximum number of concurrent sources,"
      " default: %" PRIu32
      ".\n"
      "\t--max-ports <max-ports>: maximum allowed number of touched ports,"
      " default: %" PRIu32
      ".\n"
      "\t--expire <time>: source expiration time (us).\n"
      " default: %" PRIu32 ".\n",
      DEFAULT_LAN, DEFAULT_WAN, DEFAULT_CAPACITY, DEFAULT_MAX_PORTS,
      DEFAULT_EXPIRATION_TIME);
}

void nf_config_print(void) {
  NF_INFO("\n--- Port Scanner Detector Config ---\n");

  NF_INFO("LAN Device: %" PRIu16, config.lan_device);
  NF_INFO("WAN Device: %" PRIu16, config.wan_device);
  NF_INFO("Capacity: %" PRIu32, config.capacity);
  NF_INFO("Max ports: %" PRIu32, config.max_ports);
  NF_INFO("Expiration time: %" PRIu32, config.expiration_time);

  NF_INFO("\n--- ------ ------ ---\n");
}
