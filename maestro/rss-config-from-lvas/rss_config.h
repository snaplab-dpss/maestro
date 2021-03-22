#pragma once

#include "rss_config_builder.h"

#include <vector>
#include <map>
#include <algorithm>
#include <iterator>
#include <assert.h>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class RSSConfig {
private:
  std::vector<R3S::R3S_opt_t> options;
  std::map<R3S::R3S_opt_t, std::string> options_translator;

  R3S::R3S_key_t *keys;
  unsigned n_keys;

  RSSConfig() { keys = NULL; options_translator_init(); }

  void add_option(const R3S::R3S_opt_t &option) { options.push_back(option); }

  void set_keys(const R3S::R3S_key_t *_keys, const unsigned &size) {
    keys = new R3S::R3S_key_t[size]();

    n_keys = size;
    for (auto ikey = 0; ikey < size; ikey++) {
      std::copy_n(_keys[ikey], KEY_SIZE, keys[ikey]);
    }
  }

  void options_translator_init() {
    options_translator = {
      { R3S::R3S_OPT_GENEVE_OAM, "ETH_RSS_GENEVE" },
      { R3S::R3S_OPT_VXLAN_GPE_OAM, "ETH_RSS_VXLAN" },
      { R3S::R3S_OPT_NON_FRAG_IPV4_TCP, "ETH_RSS_NONFRAG_IPV4_TCP" },
      { R3S::R3S_OPT_NON_FRAG_IPV4_UDP, "ETH_RSS_NONFRAG_IPV4_UDP" },
      { R3S::R3S_OPT_NON_FRAG_IPV4_SCTP, "ETH_RSS_NONFRAG_IPV4_SCTP" },
      { R3S::R3S_OPT_NON_FRAG_IPV6_TCP, "ETH_RSS_NONFRAG_IPV6_TCP" },
      { R3S::R3S_OPT_NON_FRAG_IPV6_UDP, "ETH_RSS_NONFRAG_IPV6_UDP" },
      { R3S::R3S_OPT_NON_FRAG_IPV6_SCTP, "ETH_RSS_NONFRAG_IPV6_SCTP" },
      { R3S::R3S_OPT_NON_FRAG_IPV6, "ETH_RSS_NONFRAG_IPV6_OTHER" },
      { R3S::R3S_OPT_FRAG_IPV6, "ETH_RSS_FRAG_IPV6" },
      { R3S::R3S_OPT_ETHERTYPE, "ETH_RSS_ETH" }
    };
  }

public:
  RSSConfig(RSSConfig& config) : RSSConfig() {
    if (config.get_keys()) {
      set_keys(config.get_keys(), config.get_n_keys());
    }

    options = config.options;
  }
  const std::vector<R3S::R3S_opt_t> &get_options() const { return options; }

  unsigned get_n_keys() { return n_keys; }
  R3S::R3S_key_t* get_keys() { return keys; }

  void dump() const {
    Logger::log() << std::hex;
    for (auto ikey = 0; ikey < n_keys; ikey++) {
      for (auto iopt = 0; iopt < options.size(); iopt++) {
        auto opt = options[iopt];

        if (options_translator.count(opt) == 0) {
          Logger::error() << "Unknown option translation: " << R3S::R3S_opt_to_string(opt) << "\n";
          exit(1);
        }

        if (iopt != 0) {
          Logger::log() << " ";
        }

        Logger::log() << options_translator.at(opt);
      }
      Logger::log() << "\n";

      for (auto i = 0; i < KEY_SIZE; i++) {
        if (i != 0) {
          Logger::log() << " ";
        }

        if (keys[ikey][i] < 0x10) {
          Logger::log() << "0";
        }

        Logger::log() << (unsigned) keys[ikey][i];
      }
      Logger::log() << "\n";
    }
    Logger::log() << std::dec;
  }

  friend class RSSConfigBuilder;

  ~RSSConfig() {
    if (keys != NULL)
      delete[] keys;
  }
};
}
