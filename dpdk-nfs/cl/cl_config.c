#include "cl_config.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "nf-util.h"
#include "nf-log.h"

const uint16_t DEFAULT_LAN = 1;
const uint16_t DEFAULT_WAN = 0;
const uint32_t DEFAULT_MAX_FLOWS = 65536;
const uint32_t DEFAULT_SKETCH_CAPACITY = 65536;
const uint16_t DEFAULT_MAX_CLIENTS = 60;
const uint64_t DEFAULT_FLOW_EXPIRATION_TIME = 1000000;     // 1s
const uint64_t DEFAULT_CLIENT_EXPIRATION_TIME = 10000000;  // 10s

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
  config.max_flows = DEFAULT_MAX_FLOWS;
  config.sketch_capacity = DEFAULT_SKETCH_CAPACITY;
  config.max_clients = DEFAULT_MAX_CLIENTS;
  config.flow_expiration_time = DEFAULT_FLOW_EXPIRATION_TIME;
  config.client_expiration_time = DEFAULT_CLIENT_EXPIRATION_TIME;

  unsigned nb_devices = rte_eth_dev_count_avail();

  struct option long_options[] = {
      {"lan", required_argument, NULL, 'l'},
      {"wan", required_argument, NULL, 'w'},
      {"max-flows", required_argument, NULL, 'f'},
      {"capacity", required_argument, NULL, 's'},
      {"max-clients", required_argument, NULL, 'c'},
      {"expire-flow", required_argument, NULL, 't'},
      {"expire-client", required_argument, NULL, 'T'},
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

      case 'f':
        config.max_flows = nf_util_parse_int(optarg, "max-flows", 10, '\0');
        if (config.max_flows <= 0) {
          PARSE_ERROR("Maximum number of flows must be strictly positive.\n");
        }
        if (!is_power_of_2(config.max_flows)) {
          PARSE_ERROR("Maximum number of flows must be a power of 2.\n");
        }
        break;

      case 's':
        config.sketch_capacity =
            nf_util_parse_int(optarg, "capacity", 10, '\0');
        if (config.sketch_capacity <= 0) {
          PARSE_ERROR("Sketch capacity must be strictly positive.\n");
        }
        break;

      case 'c':
        config.max_clients = nf_util_parse_int(optarg, "max-clients", 10, '\0');
        if (config.max_clients < 0) {
          PARSE_ERROR("Maximum number of clients must be >= 0.\n");
        }
        break;

      case 't':
        config.flow_expiration_time =
            nf_util_parse_int(optarg, "expire-flow", 10, '\0');
        if (config.flow_expiration_time <= 0) {
          PARSE_ERROR("Flow expiration time must be strictly positive.\n");
        }
        break;

      case 'T':
        config.client_expiration_time =
            nf_util_parse_int(optarg, "expire-client", 10, '\0');
        if (config.client_expiration_time <= 0) {
          PARSE_ERROR("Client expiration time must be strictly positive.\n");
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
      "\t--max-flows <max-flows>: maximum number of flows,"
      " default: %" PRIu32
      ".\n"
      "\t--capacity <capacity>: size of the clients\' sketch,"
      " default: %" PRIu32
      ".\n"
      "\t--max-clients <max-clients>: maximum allowed number of clients,"
      " default: %" PRIu16
      ".\n"
      "\t--expire-flow <time>: flow expiration time (us).\n"
      " default: %" PRIu64
      ".\n"
      "\t--expire-client <time>: client expiration time (us).\n"
      " default: %" PRIu64 ".\n",
      DEFAULT_LAN, DEFAULT_WAN, DEFAULT_MAX_FLOWS, DEFAULT_SKETCH_CAPACITY,
      DEFAULT_MAX_CLIENTS, DEFAULT_FLOW_EXPIRATION_TIME,
      DEFAULT_CLIENT_EXPIRATION_TIME);
}

void nf_config_print(void) {
  NF_INFO("\n--- Connection Limiter Config ---\n");

  NF_INFO("LAN Device: %" PRIu16, config.lan_device);
  NF_INFO("WAN Device: %" PRIu16, config.wan_device);
  NF_INFO("Max flows: %" PRIu32, config.max_flows);
  NF_INFO("Sketch size: %" PRIu32, config.sketch_capacity);
  NF_INFO("Max clients: %" PRIu16, config.max_clients);
  NF_INFO("Flow expiration time: %" PRIu64, config.flow_expiration_time);
  NF_INFO("Client expiration time: %" PRIu64, config.client_expiration_time);

  NF_INFO("\n--- ------ ------ ---\n");
}
