#include "logger.h"
#include "libvig_access.h"
#include "constraint.h"
#include "rss_config_builder.h"
#include "parser.h"

#include <iostream>

namespace R3S {
#include <r3s.h>
}

using namespace ParallelSynthesizer;

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("[ERROR] Missing arguments.");
    printf("Please provide a libvig-access-out.txt file location\n");
    return 1;
  }

  Logger::MINIMUM_LOG_LEVEL = Logger::Level::DEBUG;

  char *libvig_access_out = argv[1];

  Parser parser;
  parser.parse(libvig_access_out);

  RSSConfigBuilder rss_cfg_builder(parser.get_accesses(),
                                   parser.get_raw_constraints());

  /*
  rss_cfg_builder.build_rss_config();
  auto config = rss_cfg_builder.get_generated_rss_cfg();
  auto r3s_config = rss_cfg_builder.get_cfg();

  auto keys = config.get_keys();

  for (auto i = 0; i < config.get_n_keys(); i++) {
    Logger::log() << "Device ";
    Logger::log() << i;
    Logger::log() << ": \n";
    Logger::log() << R3S::R3S_key_to_string(keys[i]);
    Logger::log() << "\n";
  }
  */

  /*
  for (unsigned i = 0; i < 50; i++) {
    auto packets = rss_cfg_builder.generate_packets(1, 0);

    Logger::log() << "\n";
    Logger::log() << "========================================";
    Logger::log() << "\n";

    Logger::log() << "\n";
    Logger::log() << R3S_packet_to_string(packets.first);
    Logger::log() << "\n";
    Logger::log() << R3S_packet_to_string(packets.second);
    Logger::log() << "\n";

    R3S::R3S_key_hash_out_t o1, o2;

    R3S::R3S_key_hash(r3s_config, keys[1], packets.first, &o1);
    R3S::R3S_key_hash(r3s_config, keys[0], packets.second, &o2);

    if (o1 != o2) {
        Logger::error() << "Hash output mismatch";
        Logger::error() << "\n";
        Logger::error() << R3S::R3S_key_hash_output_to_string(o1);
        Logger::error() << " != ";
        Logger::error() << R3S::R3S_key_hash_output_to_string(o2);
        Logger::error() << "\n";

        exit(1);
    }
  }
  */
}
