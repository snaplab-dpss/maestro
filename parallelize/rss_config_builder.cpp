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
    R3S_status_t status;

    for (auto& constraint : constraints) {
        std::cout << "first id:  " << constraint.get_first_access().get_id() << std::endl;
        std::cout << "second id: " << constraint.get_second_access().get_id() << '\n' << std::endl;
    }

    std::vector<Z3_ast> and_args;

    for (auto& constraint : constraints) {
        for (const auto& packet_field_expr_value : constraint.get_packet_fields()) {
            PacketDependencyProcessed packet_dependency = packet_field_expr_value.second;

            Z3_ast p1_packet_field_ast;
            Z3_ast p2_packet_field_ast;

            status = R3S_packet_extract_pf(cfg, p1, packet_dependency.get_packet_field(), &p1_packet_field_ast);
            if (status != R3S_STATUS_SUCCESS) continue;

            status = R3S_packet_extract_pf(cfg, p2, packet_dependency.get_packet_field(), &p2_packet_field_ast);
            if (status != R3S_STATUS_SUCCESS) continue;

            unsigned int pf1_sz = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, p1_packet_field_ast));
            unsigned int pf2_sz = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, p2_packet_field_ast));

            unsigned int high = pf1_sz - packet_dependency.get_bytes() * 8 - 1;
            unsigned int low = high - 7;
        }
    }

    return NULL;
    
    /*
    and_args =
        (Z3_ast *)malloc(sizeof(Z3_ast) * (cnstrs->cnstrs[0].pfs.sz * 2 + 1));

    cnstr = cnstrs->cnstrs[0].cnstr;
    and_i = 0;

    printf("constraint before:\n%s\n", Z3_ast_to_string(cfg.ctx, cnstr));

    for (unsigned c = 0; c < cnstrs->cnstrs[0].pfs.sz; c++) {
        Z3_ast pf1_ast, pf2_ast;
        unsigned pf1_sz, pf2_sz;
        unsigned high, low;

        R3S_packet_extract_pf(cfg, p1, cnstrs->cnstrs[0].pfs.pfs[c].pf.pf,
                            &pf1_ast);
        R3S_packet_extract_pf(cfg, p2, cnstrs->cnstrs[0].pfs.pfs[c].pf.pf,
                            &pf2_ast);

        pf1_sz = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, pf1_ast));
        pf2_sz = Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, pf2_ast));

        high = pf1_sz - cnstrs->cnstrs[0].pfs.pfs[c].pf.bytes * 8 - 1;
        low = high - 7;

        //low = cnstrs->cnstrs[0].pfs.pfs[c].pf.bytes * 8;
        //high = low + 7;

        if (cnstrs->cnstrs[0].pfs.pfs[c].p_count == 0) {
        Z3_ast pf1_ext = Z3_mk_extract(cfg.ctx, high, low, pf1_ast);

        cnstr = ast_replace(cfg.ctx, cnstr, cnstrs->cnstrs[0].pfs.pfs[c].select,
                            pf1_ext);
        } else if (cnstrs->cnstrs[0].pfs.pfs[c].p_count == 1) {
        Z3_ast pf2_ext = Z3_mk_extract(cfg.ctx, high, low, pf2_ast);

        cnstr = ast_replace(cfg.ctx, cnstr, cnstrs->cnstrs[0].pfs.pfs[c].select,
                            pf2_ext);
        } else {
        assert(false && "Packet counter with invalid value");
        }

        assert(cnstr != NULL);
    }

    printf("p1 option %s\n", R3S_opt_to_string(p1.loaded_opt.opt));
    printf("p2 option %s\n", R3S_opt_to_string(p2.loaded_opt.opt));
    printf("constraints after:\n%s\n", Z3_ast_to_string(cfg.ctx, cnstr));

    cnstr = Z3_simplify(cfg.ctx, cnstr);

    printf("simplified:\n%s\n", Z3_ast_to_string(cfg.ctx, cnstr));

    return cnstr;
    */
}

}
