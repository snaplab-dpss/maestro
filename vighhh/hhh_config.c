#include "hhh_config.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "nf-util.h"
#include "nf-log.h"

const uint16_t DEFAULT_LAN = 1;
const uint16_t DEFAULT_WAN = 0;
const uint64_t DEFAULT_LINK_CAPACITY = 10000000; // 10Mbps
const uint8_t DEFAULT_THRESHOLD = 50;            // 50%
const uint8_t DEFAULT_MIN_PREFIX = 8;            // bits
const uint8_t DEFAULT_MAX_PREFIX = 24;           // bits
const uint64_t DEFAULT_BURST = 100000;           // 100kB
const uint32_t DEFAULT_CAPACITY = 128;           // IPs

#define PARSE_ERROR(format, ...)                                               \
  nf_config_usage();                                                           \
  fprintf(stderr, format, ##__VA_ARGS__);                                      \
  exit(EXIT_FAILURE);

void nf_config_init(int argc, char **argv) {
  // Set the default values
  config.lan_device = DEFAULT_LAN;
  config.wan_device = DEFAULT_WAN;
  config.link_capacity = DEFAULT_LINK_CAPACITY;
  config.threshold = DEFAULT_THRESHOLD;
  config.min_prefix = DEFAULT_MIN_PREFIX;
  config.max_prefix = DEFAULT_MAX_PREFIX;
  config.burst = DEFAULT_BURST;
  config.dyn_capacity = DEFAULT_CAPACITY;

  unsigned nb_devices = rte_eth_dev_count_avail();

  struct option long_options[] = {
    { "lan", required_argument, NULL, 'l' },
    { "wan", required_argument, NULL, 'w' },
    { "link", required_argument, NULL, 'r' },
    { "threshold", required_argument, NULL, 't' },
    { "min-prefix", required_argument, NULL, 'm' },
    { "max-prefix", required_argument, NULL, 'M' },
    { "burst", required_argument, NULL, 'b' },
    { "capacity", required_argument, NULL, 'c' },
    { NULL, 0, NULL, 0 }
  };

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

      case 'r':
        config.link_capacity = nf_util_parse_int(optarg, "link", 10, '\0');
        if (config.link_capacity == 0) {
          PARSE_ERROR("Link capacity must be strictly positive.\n");
        }
        break;

      case 't':
        config.threshold = nf_util_parse_int(optarg, "threshold", 10, '\0');
        if (config.threshold == 0 || config.threshold > 100) {
          PARSE_ERROR(
              "Heavy hitter threshold percentage must be in > 0 and <= 100.\n");
        }
        break;

      case 'm':
        config.min_prefix = nf_util_parse_int(optarg, "min_prefix", 10, '\0');
        if (config.min_prefix > 32) {
          PARSE_ERROR("Minimum IP prefix size must be > 0 and <= 32.\n");
        }
        break;

      case 'M':
        config.max_prefix = nf_util_parse_int(optarg, "max_prefix", 10, '\0');
        if (config.max_prefix < config.min_prefix || config.max_prefix > 32) {
          PARSE_ERROR(
              "Maximum IP prefix size must be >= min_prefix and <= 32.\n");
        }
        break;

      case 'b':
        config.burst = nf_util_parse_int(optarg, "burst", 10, '\0');
        if (config.burst == 0) {
          PARSE_ERROR("HHH burst size must be strictly positive.\n");
        }
        break;

      case 'c':
        config.dyn_capacity = nf_util_parse_int(optarg, "capacity", 10, '\0');
        if (config.dyn_capacity <= 0) {
          PARSE_ERROR("Flow table size must be strictly positive.\n");
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
  NF_INFO("Usage:\n"
          "[DPDK EAL options] --\n"
          "\t--lan <device>: LAN device,"
          " default: %" PRIu16 ".\n"
          "\t--wan <device>: WAN device,"
          " default: %" PRIu16 ".\n"
          "\t--link <link>: link capacity in bits/s,"
          " default: %" PRIu64 ".\n"
          "\t--threshold <threshold>: heavy hitter threshold integer in %%,"
          " default: %" PRIu8 ".\n"
          "\t--min-prefix <min_prefix>: minimum IP prefix size in bits,"
          " default: %" PRIu8 ".\n"
          "\t--max-prefix <max_prefix>: maximum IP prefix size in bits,"
          " default: %" PRIu8 ".\n"
          "\t--burst <size>: HHH burst size in bytes,"
          " default: %" PRIu64 ".\n"
          "\t--capacity <n>: HHH table capacity,"
          " default: %" PRIu32 ".\n",
          DEFAULT_LAN, DEFAULT_WAN, DEFAULT_LINK_CAPACITY, DEFAULT_THRESHOLD,
          DEFAULT_MIN_PREFIX, DEFAULT_MAX_PREFIX, DEFAULT_BURST,
          DEFAULT_CAPACITY);
}

void nf_config_print(void) {
  NF_INFO("\n--- Hierarchical Heavy Hitter Config ---\n");

  NF_INFO("LAN Device: %" PRIu16, config.lan_device);
  NF_INFO("WAN Device: %" PRIu16, config.wan_device);
  NF_INFO("Link capacity: %" PRIu64, config.link_capacity);
  NF_INFO("Threshold: %" PRIu8, config.threshold);
  NF_INFO("Min prefix: %" PRIu8, config.min_prefix);
  NF_INFO("Max prefix: %" PRIu8, config.max_prefix);
  NF_INFO("Burst: %" PRIu64, config.burst);
  NF_INFO("Capacity: %" PRIu16, config.dyn_capacity);

  NF_INFO("\n--- ------ ------ ---\n");
}
