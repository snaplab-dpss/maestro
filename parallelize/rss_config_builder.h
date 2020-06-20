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

    RSSConfig rss_config;
    std::vector<R3S::R3S_pf_t> unique_packet_fields_dependencies;
    std::vector<R3S::R3S_cnstrs_func> solver_constraints_generators;

private:
    void find_compatible_rss_config_options();
    void load_rss_config_options();
    void load_solver_constraints_generators();

    void merge_unique_packet_field_dependencies(const std::vector<R3S::R3S_pf_t>& packet_fields);

public:
    RSSConfigBuilder(
        std::vector<LibvigAccess>  accesses,
        std::vector<RawConstraint> raw_constraints
    ) {
        R3S_cfg_init(&cfg);
        
        for (const auto& raw_constraint : raw_constraints) {
            LibvigAccess& first = LibvigAccess::find(accesses, raw_constraint.get_first_access_id());
            LibvigAccess& second = LibvigAccess::find(accesses, raw_constraint.get_second_access_id());
            
            if (first.get_object() != second.get_object()) {
                std::cerr << "[WARNING] Constraint between different objects doesn't make any sense" << std::endl;
                continue;
            }

            merge_unique_packet_field_dependencies(first.get_unique_packet_fields());
            merge_unique_packet_field_dependencies(second.get_unique_packet_fields());
            
            constraints.emplace_back(first, second, cfg.ctx, raw_constraint);
        }

        std::cout << "\nUnique packet field dependencies:" << std::endl;
        for (auto& pf : unique_packet_fields_dependencies) {
            std::cout << "  " << R3S_pf_to_string(pf) << std::endl;
        }
    }

    const R3S::R3S_cfg_t& get_cfg() const { return cfg; }
    const std::vector<Constraint>& get_constraints() const { return constraints; }

    static R3S::Z3_ast ast_replace(R3S::Z3_context ctx, R3S::Z3_ast root, R3S::Z3_ast target, R3S::Z3_ast dst);
    static R3S::Z3_ast make_solver_constraints(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2);

    void build();
};

}
