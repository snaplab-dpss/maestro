#include <iostream>
#include <algorithm>

#include "rss_config_builder.h"

namespace ParallelSynthesizer {

void RSSConfigBuilder::merge_unique_packet_field_dependencies(const std::vector<R3S_pf_t>& packet_fields) {
    for (auto& packet_field : packet_fields) {
        auto found_it = std::find(unique_packet_fields_dependencies.begin(), unique_packet_fields_dependencies.end(), packet_field);
        
        if (found_it != unique_packet_fields_dependencies.end())
            continue;

        unique_packet_fields_dependencies.push_back(packet_field);
    }
}

void RSSConfigBuilder::load_rss_config_options() {
    for (const auto& option : rss_config.options)
        R3S_cfg_load_opt(&cfg, option);
    
    std::cout << "\nR3S configuration:" << std::endl;
    std::cout << R3S_cfg_to_string(cfg) << std::endl;
}

void RSSConfigBuilder::find_compatible_rss_config_options() {
    if (unique_packet_fields_dependencies.size() == 0) {
        std::cout << "[WARNING] No dependencies on packet fields. Nothing we can do :(" << std::endl;
        return;
    }

    // the R3S library is written in C
    R3S_opt_t *opts;
    size_t opts_sz;

    R3S_opts_from_pfs(
        &unique_packet_fields_dependencies[0],
        unique_packet_fields_dependencies.size(),
        &opts,
        &opts_sz
    );

    rss_config.options = std::vector<R3S_opt_t>(opts, opts + opts_sz);
}

void RSSConfigBuilder::load_solver_constraints_generators() {
    solver_constraints_generators.reserve(cfg.n_keys);

    // TODO: more than 1 key scenario

    solver_constraints_generators[0] = &RSSConfigBuilder::make_solver_constraints;
}

void RSSConfigBuilder::build() {
    find_compatible_rss_config_options();
    load_rss_config_options();

    R3S_set_user_data(&cfg, (void *) &constraints);

    R3S_packet_t p1, p2;
    R3S_status_t status;

    R3S_packet_rand(cfg, &p1);

    if ((status = R3S_packet_from_cnstrs(cfg, p1, &RSSConfigBuilder::make_solver_constraints, &p2)) !=
        R3S_STATUS_SUCCESS) {
      printf("ERROR: %s\n", R3S_status_to_string(status));
      exit(1);
    }

    std::cout << "[Generated packets]" << "\n";
    std::cout << R3S_packet_to_string(p1) << "\n";
    std::cout << R3S_packet_to_string(p2) << std::endl;

}

Z3_ast RSSConfigBuilder::ast_replace(Z3_context ctx, Z3_ast root, Z3_ast target, Z3_ast dst) {
    if (Z3_get_ast_kind(ctx, root) != Z3_APP_AST)
        return root;

    Z3_app app = Z3_to_app(ctx, root);
    unsigned num_fields = Z3_get_app_num_args(ctx, app);
    Z3_ast *updated_args = (Z3_ast *) malloc(sizeof(Z3_ast) * num_fields);

    for (unsigned i = 0; i < num_fields; i++) {
        updated_args[i] =
            Z3_is_eq_ast(ctx, Z3_get_app_arg(ctx, app, i), target)
                ? dst
                : ast_replace(ctx, Z3_get_app_arg(ctx, app, i), target, dst);
    }

    root = Z3_update_term(ctx, root, num_fields, updated_args);
    free(updated_args);

    return root;
}

Z3_ast RSSConfigBuilder::make_solver_constraints(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2) {
    std::vector<Constraint> constraints = *((std::vector<Constraint>*) R3S_get_user_data(cfg));
    std::vector<Z3_ast> generated_constraints;

    for (auto& constraint : constraints) {
        Z3_ast& constraint_expression = constraint.get_expression();

        std::cout << "\n";
        std::cout << "=================================================" << "\n";

        std::cout << "\n";
        std::cout << "[Packet options]" << "\n";
        std::cout << "p1 option: " << R3S_opt_to_string(p1.loaded_opt.opt) << "\n";
        std::cout << "p2 option: " << R3S_opt_to_string(p2.loaded_opt.opt) << "\n";

        std::cout << "\n";
        std::cout << "[Access]" << "\n";
        std::cout << "first:  "
                  << constraint.get_first_access().get_id() << " (id) "
                  << constraint.get_first_access().get_device() << " (device) "
                  << constraint.get_first_access().get_object() << " (object) "
                  << "\n";
        std::cout << "second: "
                  << constraint.get_second_access().get_id() << " (id) "
                  << constraint.get_second_access().get_device() << " (device) "
                  << constraint.get_second_access().get_object() << " (object) "
                  << "\n";


        int last_index = -1;

        std::cout << "\n";
        std::cout << "[Constraint before]" << "\n";
        std::cout << Z3_ast_to_string(cfg.ctx, constraint_expression) << "\n";

        for (const auto& packet_field_expr_value : constraint.get_packet_fields()) {
            PacketFieldExpression packet_dependency_expr = packet_field_expr_value.first;
            PacketDependencyProcessed packet_dependency_value = packet_field_expr_value.second;

            R3S_packet_ast_t target_packet = (packet_dependency_expr.get_index() > last_index) ? p1 : p2;
            
            Z3_ast packet_field_ast;
            R3S_status_t status;

            status = R3S_packet_extract_pf(cfg, target_packet, packet_dependency_value.get_packet_field(), &packet_field_ast);
            if (status != R3S_STATUS_SUCCESS) continue;

            unsigned int packet_field_ast_size = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, packet_field_ast));

            unsigned int high = packet_field_ast_size - packet_dependency_value.get_bytes() * 8 - 1;
            unsigned int low = high - 7;

            Z3_ast packet_field_byte_ast = Z3_mk_extract(cfg.ctx, high, low, packet_field_ast);
            
            constraint_expression = ast_replace(cfg.ctx, constraint_expression, packet_dependency_expr.get_expression(), packet_field_byte_ast);

            last_index = packet_dependency_expr.get_index();
        }

        generated_constraints.push_back(constraint_expression);

        std::cout << "\n";
        std::cout << "[Constraint after]" << "\n";
        std::cout << Z3_ast_to_string(cfg.ctx, constraint_expression) << "\n";

        std::cout << "\n";
        std::cout << "[Simplified]" << "\n";
        std::cout << Z3_ast_to_string(cfg.ctx, Z3_simplify(cfg.ctx, constraint_expression)) << std::endl;
    }

    Z3_ast final_constraint = Z3_mk_and(cfg.ctx, generated_constraints.size(), &generated_constraints[0]);
    //return final_constraint;
    return generated_constraints[0];
}

}
