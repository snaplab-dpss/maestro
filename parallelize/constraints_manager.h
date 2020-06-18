#pragma once

#include "libvig_access.h"
#include "constraint.h"

#include <z3.h>
#include <r3s.h>
#include <vector>

namespace ParallelSynthesizer {

class ConstraintsManager {

private:
    R3S_cfg_t cfg;
    std::vector<Constraint> constraints;

public:
    ConstraintsManager(
        std::vector<LibvigAccess>  accesses,
        std::vector<RawConstraint> raw_constraints
    ) {
        R3S_cfg_init(&cfg);
        
        for (const auto& raw_constraint : raw_constraints) {
            LibvigAccess& first = LibvigAccess::find(accesses, raw_constraint.get_first_access_id());
            LibvigAccess& second = LibvigAccess::find(accesses, raw_constraint.get_second_access_id());
            
            if (first.get_object() != second.get_object()) {
                std::cerr << "[ERROR] Constraint between objects doesn't make any sense" << std::endl;
                exit(1);
            }
            
            constraints.emplace_back(first, second, cfg.ctx, raw_constraint);
        }
    }

};

}
