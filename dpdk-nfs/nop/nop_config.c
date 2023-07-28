#include "nop_config.h"

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>

#include "nf.h"
#include "nf-util.h"
#include "nf-log.h"
#include "nf-parse.h"

#define PARSE_ERROR(format, ...)          \
  nf_config_usage();                      \
  fprintf(stderr, format, ##__VA_ARGS__); \
  exit(EXIT_FAILURE);

void nf_config_init(int argc, char **argv) {
  uint16_t nb_devices = rte_eth_dev_count_avail();

  struct option long_options[] = {{"lan", required_argument, NULL, 'l'},
                                  {"wan", required_argument, NULL, 'w'},
                                  {NULL, 0, NULL, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "pl:", long_options, NULL)) != EOF) {
    unsigned device;
    switch (opt) {
      case 'l':
        config.lan_device = nf_util_parse_int(optarg, "lan", 10, '\0');
        if (config.lan_device >= nb_devices) {
          PARSE_ERROR("LAN device does not exist.\n");
        }
        break;

      case 'w':
        config.wan_device = nf_util_parse_int(optarg, "wan", 10, '\0');
        if (config.wan_device >= nb_devices) {
          PARSE_ERROR("WAN device does not exist.\n");
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
  NF_INFO(
      "Usage:\n"
      "[DPDK EAL options] --\n"
      "\t--lan <device>: set device to be the LAN device\n"
      "\t--wan <device>: set device to be the external one.\n");
}

void nf_config_print(void) {
  NF_INFO("\n--- NOP Config ---\n");

  NF_INFO("LAN device: %" PRIu16, config.lan_device);
  NF_INFO("WAN device: %" PRIu16, config.wan_device);

  NF_INFO("\n--- --- ------ ---\n");
}
