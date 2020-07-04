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

  for (unsigned i = 0; i < 1; i++) {
    auto packets_pair = rss_cfg_builder.generate_packets();
    Logger::log() << "\n";
    Logger::log() << "[Generated packets]";
    Logger::log() << "\n";

    Logger::log() << "\n";
    Logger::log() << R3S_packet_to_string(packets_pair.first);
    Logger::log() << "\n";
    Logger::log() << R3S_packet_to_string(packets_pair.second);
    Logger::log() << "\n";
  }

  /*
  rss_cfg_builder.build();

  auto config = rss_cfg_builder.get_generated_rss_cfg();

  Logger::log() << "Generated key:";
  Logger::log() << "\n";
  Logger::log() << R3S::R3S_key_to_string(config.get_key());
  */
}
