#pragma once

#include "constraint.h"
#include "rss_config.h"
#include "libvig_access.h"

#include <vector>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class RSSConfigBuilder {

private:
    R3S::R3S_cfg_t cfg;
    std::vector<Constraint> constraints;

    std::vector<unsigned int> unique_devices;
    std::vector< std::pair<LibvigAccess, LibvigAccess> > unique_access_pairs;
    std::vector<R3S::R3S_pf_t> unique_packet_fields_dependencies;
    std::vector<R3S::R3S_cnstrs_func> solver_constraints_generators;

    RSSConfig rss_config;

private:
    void find_compatible_rss_config_options();
    void load_rss_config_options();
    void load_solver_constraints_generators();

    void merge_unique_packet_field_dependencies(const std::vector<R3S::R3S_pf_t>& packet_fields);
    bool is_access_pair_already_stored(const std::pair<LibvigAccess, LibvigAccess>& pair);

public:
    RSSConfigBuilder(
        std::vector<LibvigAccess>  accesses,
        std::vector<RawConstraint> raw_constraints
    ) {
        R3S_cfg_init(&cfg);

        for (const auto& raw_constraint : raw_constraints) {
            LibvigAccess& first = LibvigAccess::find_by_id(accesses, raw_constraint.get_first_access_id());
            LibvigAccess& second = LibvigAccess::find_by_id(accesses, raw_constraint.get_second_access_id());

            if (first.get_object() != second.get_object()) {
                Logger::warn() << "Constraint between different objects doesn't make any sense" << "\n";
                continue;
            }

            std::pair<LibvigAccess, LibvigAccess> access(first, second);

            if (is_access_pair_already_stored(access))
                continue;

            if (std::find(unique_devices.begin(), unique_devices.end(), first.get_device()) == unique_devices.end())
                unique_devices.push_back(first.get_device());
            
            if (std::find(unique_devices.begin(), unique_devices.end(), second.get_device()) == unique_devices.end())
                unique_devices.push_back(second.get_device());

            merge_unique_packet_field_dependencies(first.get_unique_packet_fields());
            merge_unique_packet_field_dependencies(second.get_unique_packet_fields());
            
            constraints.emplace_back(first, second, cfg.ctx, raw_constraint);
            unique_access_pairs.push_back(access);
        }

        Logger::log() << "\n";
        Logger::log() << "Packet field dependencies:";
        Logger::log() << "\n";
        for (auto& pf : unique_packet_fields_dependencies) {
            Logger::log() << "  " << R3S_pf_to_string(pf);
            Logger::log() << "\n";
        }

        Logger::log() << "\n";
        Logger::log() << "Devices:";
        Logger::log() << "\n";
        for (auto& device : unique_devices) {
            Logger::log() << "  " << device;
            Logger::log() << "\n";
        }
    }

    const R3S::R3S_cfg_t& get_cfg() const { return cfg; }
    const std::vector<Constraint>& get_constraints() const { return constraints; }

    static R3S::Z3_ast ast_replace(R3S::Z3_context ctx, R3S::Z3_ast root, R3S::Z3_ast target, R3S::Z3_ast dst);
    static R3S::Z3_ast make_solver_constraints(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2);

    void build();
};

}
