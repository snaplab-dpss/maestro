#pragma once

#include "rss_config_builder.h"

#include <vector>
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

  R3S::R3S_key_t *keys;
  unsigned n_keys;

public:
  RSSConfig() { keys = NULL; }
  RSSConfig(RSSConfig& config) : RSSConfig() {
    if (config.get_keys()) {
      set_keys(config.get_keys(), config.get_n_keys());
    }
  }

  void add_option(const R3S::R3S_opt_t &option) { options.push_back(option); }

  void set_keys(const R3S::R3S_key_t *_keys, const unsigned &size) {
    keys = new R3S::R3S_key_t[size]();

    n_keys = size;
    for (auto ikey = 0; ikey < size; ikey++) {
      std::copy_n(_keys[ikey], KEY_SIZE, keys[ikey]);
    }
  }

public:
  const std::vector<R3S::R3S_opt_t> &get_options() const { return options; }

  unsigned get_n_keys() { return n_keys; }
  R3S::R3S_key_t* get_keys() { return keys; }

  friend class RSSConfigBuilder;

  ~RSSConfig() {
    if (keys != NULL)
      delete[] keys;
  }
};
}
