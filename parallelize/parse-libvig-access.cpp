#include "logger.h"
#include "libvig_access.h"
#include "constraint.h"
#include "rss_config_builder.h"
#include "parser.h"

#include <iostream>

namespace R3S {
#include <r3s.h>
}

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("[ERROR] Missing arguments.");
    printf("Please provide a libvig-access-out.txt file location\n");
    return 1;
  }

  ParallelSynthesizer::Logger::MINIMUM_LOG_LEVEL = ParallelSynthesizer::Logger::Level::LOG;

  char *libvig_access_out = argv[1];

  R3S::R3S_cnstrs_func cnstrs[1];
  R3S::R3S_status_t status;

  ParallelSynthesizer::Parser parser;

  parser.parse(libvig_access_out);

  for (auto &access : parser.get_accesses()) {
    ParallelSynthesizer::Logger::debug() << "==========================\n";
    ParallelSynthesizer::Logger::debug() << "id:     " << access.get_id() << '\n';
    ParallelSynthesizer::Logger::debug() << "device: " << access.get_device() << '\n';
    ParallelSynthesizer::Logger::debug() << "object: " << access.get_object() << '\n';

    for (auto &dep : access.get_dependencies()) {
      if (dep.has_valid_packet_field())
        ParallelSynthesizer::Logger::debug() << "pf:    " << R3S_pf_to_string(dep.get_packet_field()) << '\n';
    }

    ParallelSynthesizer::Logger::debug() << '\n';
  }

  for (auto &raw_constraint : parser.get_raw_constraints()) {
    ParallelSynthesizer::Logger::debug() << "==========================\n";
    ParallelSynthesizer::Logger::debug() << "first:      " << raw_constraint.get_first_access_id() << '\n';
    ParallelSynthesizer::Logger::debug() << "second:     " << raw_constraint.get_second_access_id();
    ParallelSynthesizer::Logger::debug() << '\n';
    ParallelSynthesizer::Logger::debug() << "expression: " << raw_constraint.get_expression() << '\n';
    ParallelSynthesizer::Logger::debug() << '\n';
  }

  ParallelSynthesizer::RSSConfigBuilder rss_cfg_builder(parser.get_accesses(),
                                                  parser.get_raw_constraints());

  rss_cfg_builder.build();
}
