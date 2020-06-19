#pragma once

#include <vector>

#include "rss_config_builder.h"

#include <r3s.h>

namespace ParallelSynthesizer {

class RSSConfig {
private:
    std::vector<R3S_opt_t> options;
    R3S_key_t key;

    RSSConfig() {}
public:

    const std::vector<R3S_opt_t>& get_options() { return options; }
    const R3S_key_t& get_key() { return key; }

    friend class RSSConfigBuilder;
};

}
