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

    R3S::R3S_key_t* keys;
    unsigned n_keys;

    RSSConfig() {}

    void add_option(const R3S::R3S_opt_t& option) { options.push_back(option); }

    void set_keys(R3S::R3S_key_t* _keys, const unsigned& size) {
      keys = new R3S::R3S_key_t[size]();

      n_keys = size;
      for (auto ikey = 0; ikey < size; ikey++) {
        std::copy_n(_keys[ikey], KEY_SIZE, keys[ikey]);
      }
    }

public:
    const std::vector<R3S::R3S_opt_t>& get_options() const { return options; }
    const unsigned& get_n_keys() const { return n_keys; }

    R3S::R3S_key_t&& get_key(unsigned i) const {
      assert(i < n_keys);
      return std::forward<R3S::R3S_key_t>(keys[i]);
    }

    friend class RSSConfigBuilder;

    ~RSSConfig() {
      delete[] keys;
    }
};
}
