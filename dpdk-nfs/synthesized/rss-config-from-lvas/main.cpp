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

  Logger::MINIMUM_LOG_LEVEL = Logger::Level::DEBUG;

  if (argc < 2) {
    Logger::error() << "[ERROR] Missing arguments.";
    Logger::error()
        << "Please provide an LVA file location, or \"--rand [devices]\".\n";
    return 1;
  }

  std::string arg = argv[1];

  if (arg == "--rand") {
    if (argc < 3) {
      Logger::error() << "[ERROR] Missing arguments.";
      Logger::error() << "Please provide an number of devices to go with the "
                         "--rand flag.\n";
      return 1;
    }

    std::string::size_type sz;
    int devices = std::stoi(argv[2], &sz);

    RSSConfig config;
    config.randomize(devices);

    auto keys = config.get_keys();

    for (auto i = 0; i < config.get_n_keys(); i++) {
      Logger::debug() << "Device ";
      Logger::debug() << i;
      Logger::debug() << ": \n";
      Logger::debug() << R3S::R3S_key_to_string(keys[i]);
      Logger::debug() << "\n";
    }

    config.dump();
  } else {
    Parser parser(arg);

    RSSConfigBuilder rss_cfg_builder(parser.get_accesses(),
                                     parser.get_call_paths_constraints());

    rss_cfg_builder.build_rss_config();
    auto config = rss_cfg_builder.get_generated_rss_cfg();

    auto keys = config.get_keys();

    for (auto i = 0; i < config.get_n_keys(); i++) {
      Logger::debug() << "Device ";
      Logger::debug() << i;
      Logger::debug() << ": \n";
      Logger::debug() << R3S::R3S_key_to_string(keys[i]);
      Logger::debug() << "\n";
    }

    config.dump();
  }
}
