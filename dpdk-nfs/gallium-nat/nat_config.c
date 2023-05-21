#include "nat_config.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "nf-log.h"
#include "nf-parse.h"
#include "nf-util.h"
#include "nf.h"

#define PARSE_ERROR(format, ...)                                               \
  nf_config_usage();                                                           \
  fprintf(stderr, format, ##__VA_ARGS__);                                      \
  exit(EXIT_FAILURE);

void nf_config_init(int argc, char **argv) {
  uint16_t nb_devices = rte_eth_dev_count_avail();

  struct option long_options[] = { { "lan", required_argument, NULL, 'l' },
                                   { "wan", required_argument, NULL, 'w' },
                                   { "extip", required_argument, NULL, 'i' },
                                   { "max-flows", required_argument, NULL,
                                     'f' },
                                   { NULL, 0, NULL, 0 } };

  int opt;
  while ((opt = getopt_long(argc, argv, "l:w:i:f:", long_options, NULL)) !=
         EOF) {
    unsigned device;
    switch (opt) {
      case 'l':
        config.lan_device = nf_util_parse_int(optarg, "lan", 10, '\0');
        if (config.lan_device >= nb_devices) {
          PARSE_ERROR("Main LAN device does not exist.\n");
        }
        break;

      case 'w':
        config.wan_device = nf_util_parse_int(optarg, "wan", 10, '\0');
        if (config.wan_device >= nb_devices) {
          PARSE_ERROR("WAN device does not exist.\n");
        }
        break;

      case 'i':
        if (!nf_parse_ipv4addr(optarg, &(config.external_addr))) {
          PARSE_ERROR("Invalid external IP address: %s\n", optarg);
        }
        break;

      case 'f':
        config.max_flows = nf_util_parse_int(optarg, "max-flows", 10, '\0');
        if (config.max_flows <= 0) {
          PARSE_ERROR("Flow table size must be strictly positive.\n");
        }
        break;

      default:
        PARSE_ERROR("Unknown option.\n");
        break;
    }
  }

  // Reset getopt
  optind = 1;
}

void nf_config_usage(void) {
  NF_INFO("Usage:\n"
          "[DPDK EAL options] --\n"
          "\t--lan <device>: set device to be the main LAN device.\n"
          "\t--wan <device>: set device to be the external one.\n"
          "\t--extip <ip>: external IP address.\n"
          "\t--max-flows <n>: flow table capacity.\n");
}

void nf_config_print(void) {
  NF_INFO("\n--- Gallium NAT Config ---\n");

  NF_INFO("LAN device: %" PRIu16, config.lan_device);
  NF_INFO("WAN device: %" PRIu16, config.wan_device);

  char *ext_ip_str = nf_rte_ipv4_to_str(config.external_addr);
  NF_INFO("External IP: %s", ext_ip_str);
  free(ext_ip_str);

  NF_INFO("Max flows: %" PRIu32, config.max_flows);

  NF_INFO("\n--- --- ------ ---\n");
}
