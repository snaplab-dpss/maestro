#pragma once

#include "rss_config_builder.h"

#include <vector>
#include <map>
#include <algorithm>
#include <iterator>
#include <assert.h>

namespace RS3 {
#include <rs3.h>
}

namespace ParallelSynthesizer {

class RSSConfig {
private:
  std::vector<RS3::RS3_opt_t> options;
  std::map<RS3::RS3_opt_t, std::string> options_translator;

  RS3::RS3_key_t *keys;
  unsigned n_keys;

  void add_option(const RS3::RS3_opt_t &option) { options.push_back(option); }

  void set_keys(RS3::RS3_key_t *_keys, const unsigned &size) {
    keys = new RS3::RS3_key_t[size]();

    n_keys = size;
    for (auto ikey = 0; ikey < size; ikey++) {
      std::copy_n(_keys[ikey], KEY_SIZE, keys[ikey]);
    }
  }

  void options_translator_init() {
    options_translator = {
      { RS3::RS3_OPT_GENEVE_OAM, "ETH_RSS_GENEVE" },
      { RS3::RS3_OPT_VXLAN_GPE_OAM, "ETH_RSS_VXLAN" },
      { RS3::RS3_OPT_NON_FRAG_IPV4_TCP, "ETH_RSS_NONFRAG_IPV4_TCP" },
      { RS3::RS3_OPT_NON_FRAG_IPV4_UDP, "ETH_RSS_NONFRAG_IPV4_UDP" },
      { RS3::RS3_OPT_NON_FRAG_IPV4_SCTP, "ETH_RSS_NONFRAG_IPV4_SCTP" },
      { RS3::RS3_OPT_NON_FRAG_IPV6_TCP, "ETH_RSS_NONFRAG_IPV6_TCP" },
      { RS3::RS3_OPT_NON_FRAG_IPV6_UDP, "ETH_RSS_NONFRAG_IPV6_UDP" },
      { RS3::RS3_OPT_NON_FRAG_IPV6_SCTP, "ETH_RSS_NONFRAG_IPV6_SCTP" },
      { RS3::RS3_OPT_NON_FRAG_IPV6, "ETH_RSS_NONFRAG_IPV6_OTHER" },
      { RS3::RS3_OPT_FRAG_IPV6, "ETH_RSS_FRAG_IPV6" },
      { RS3::RS3_OPT_ETHERTYPE, "ETH_RSS_ETH" }
    };
  }

public:
  RSSConfig() { keys = NULL; options_translator_init(); }

  RSSConfig(RSSConfig& config) : RSSConfig() {
    if (config.get_keys()) {
      set_keys(config.get_keys(), config.get_n_keys());
    }

    options = config.options;
  }

  void randomize(unsigned int devices) {
    RS3::RS3_cfg_t cfg;

    RS3::RS3_cfg_init(&cfg);
    RS3::RS3_cfg_set_skew_analysis(cfg, false);

    for (int i = RS3::RS3_FIRST_OPT; i <= RS3::RS3_LAST_OPT; i++) {
      auto opt = static_cast<RS3::RS3_opt_t>(i);
      add_option(opt);
      RS3::RS3_cfg_load_opt(cfg, opt);
    }

    keys = new RS3::RS3_key_t[devices]();
    n_keys = devices;

    for (auto device = 0; device < devices; device++) {
      RS3::RS3_key_t key;
      RS3::RS3_key_rand(cfg, key);
      std::copy_n(key, KEY_SIZE, keys[device]);
    }
  }

  const std::vector<RS3::RS3_opt_t> &get_options() const { return options; }

  unsigned get_n_keys() { return n_keys; }
  RS3::RS3_key_t* get_keys() { return keys; }

  void dump() const {
    Logger::log() << std::hex;
    for (auto ikey = 0; ikey < n_keys; ikey++) {
      for (auto iopt = 0; iopt < options.size(); iopt++) {
        auto opt = options[iopt];

        if (options_translator.count(opt) == 0) {
          Logger::error() << "Unknown option translation: " << RS3::RS3_opt_to_string(opt) << "\n";
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
