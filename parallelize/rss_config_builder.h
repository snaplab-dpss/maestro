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
    void load_rss_config_options();
    void load_solver_constraints_generators();
    int get_device_index(unsigned int device) const;

    void merge_unique_packet_field_dependencies(const std::vector<R3S::R3S_pf_t>& packet_fields);
    bool is_access_pair_already_stored(const std::pair<LibvigAccess, LibvigAccess>& pair);

public:
    RSSConfigBuilder(
        const std::vector<LibvigAccess>&  accesses,
        const std::vector<RawConstraint>& raw_constraints
    ) {
        R3S::R3S_cfg_init(&cfg);
        R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);
        R3S::R3S_cfg_set_skew_analysis(cfg, false);

        fill_unique_devices(accesses);
        const auto trimmed_accesses = analyze_operations_on_objects(accesses);

        for (const auto& raw_constraint : raw_constraints) {
            const LibvigAccess& first = LibvigAccess::find_by_id(trimmed_accesses, raw_constraint.get_first_access_id());
            const LibvigAccess& second = LibvigAccess::find_by_id(trimmed_accesses, raw_constraint.get_second_access_id());

            if (first.get_object() != second.get_object()) {
                Logger::warn() << "Constraint between different objects doesn't make any sense" << "\n";
                continue;
            }

            std::pair<LibvigAccess, LibvigAccess> access(first, second);

            if (is_access_pair_already_stored(access))
                continue;

            merge_unique_packet_field_dependencies(first.get_unique_packet_fields());
            merge_unique_packet_field_dependencies(second.get_unique_packet_fields());

            const auto& new_constraint = Constraint(first, second, ctx, raw_constraint);
            constraints.emplace_back(std::move(new_constraint));

            unique_access_pairs.push_back(access);
        }

        Logger::log() << "\n";
        Logger::log() << "Packet field dependencies:";
        Logger::log() << "\n";
        for (auto& pf : unique_packet_fields_dependencies) {
            Logger::log() << "  " << R3S::R3S_pf_to_string(pf);
            Logger::log() << "\n";
        }

        Logger::log() << "\n";
        Logger::log() << "Devices:";
        Logger::log() << "\n";
        for (const auto& device : unique_devices) {
            Logger::log() << "  " << device;
            Logger::log() << "\n";
        }

        R3S::R3S_cfg_set_number_of_keys(cfg, unique_devices.size());
        load_rss_config_options();

        R3S::R3S_cfg_set_user_data(cfg, (void *) &constraints);

        Logger::log() << "\nR3S configuration:\n" << R3S::R3S_cfg_to_string(cfg) << "\n";
    }

    const R3S::R3S_cfg_t& get_cfg() const { return cfg; }
    const std::vector<Constraint>& get_constraints() const { return constraints; }
    const RSSConfig& get_generated_rss_cfg() const { return rss_config; }

    static R3S::Z3_ast ast_replace(R3S::Z3_context ctx, R3S::Z3_ast root, R3S::Z3_ast target, R3S::Z3_ast dst);
    static R3S::Z3_ast make_solver_constraints(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2);

    void build_rss_config();
    void fill_unique_devices(const std::vector<LibvigAccess>& accesses);
    const std::vector<LibvigAccess> analyze_operations_on_objects(const std::vector<LibvigAccess>& accesses);

    std::pair<R3S::R3S_packet_t, R3S::R3S_packet_t> generate_packets(unsigned device1, unsigned device2);

    ~RSSConfigBuilder() {
        R3S::R3S_cfg_delete(cfg);
    }
};

}
