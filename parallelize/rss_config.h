#pragma once

#include "rss_config_builder.h"

#include <vector>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class RSSConfig {
private:
    std::vector<R3S::R3S_opt_t> options;
    R3S::R3S_key_t key;

    RSSConfig() {}
public:

    const std::vector<R3S::R3S_opt_t>& get_options() { return options; }
    R3S::R3S_key_t&& get_key() { return std::forward<R3S::R3S_key_t>(key); }

    friend class RSSConfigBuilder;
};

}
