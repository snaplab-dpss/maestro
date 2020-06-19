#include <iostream>

#include "libvig_access.h"
#include "constraint.h"
#include "rss_config_builder.h"
#include "parser.h"

#include <r3s.h>
#include <z3.h>

/*
Z3_ast ast_replace(Z3_context ctx, Z3_ast root, Z3_ast target, Z3_ast dst) {
  if (Z3_get_ast_kind(ctx, root) != Z3_APP_AST)
    return root;

  Z3_app app = Z3_to_app(ctx, root);
  unsigned num_fields = Z3_get_app_num_args(ctx, app);
  Z3_ast *updated_args = (Z3_ast *)malloc(sizeof(Z3_ast) * num_fields);

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
*/
/*
Z3_ast mk_cnstrs(R3S_cfg_t cfg, R3S_packet_ast_t p1, R3S_packet_ast_t p2) {
  R3S_status_t status;
  constraints_t *cnstrs;
  Z3_ast *and_args;
  unsigned and_i;
  Z3_ast cnstr;

  cnstrs = (constraints_t *)R3S_get_user_data(cfg);
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
}

void validate(R3S_cfg_t cfg) {
  R3S_packet_t p1, p2;
  R3S_status_t status;

  for (int i = 0; i < 25; i++) {
    R3S_packet_rand(cfg, &p1);

    if ((status = R3S_packet_from_cnstrs(cfg, p1, &mk_cnstrs, &p2)) !=
        R3S_STATUS_SUCCESS) {
      printf("ERROR: %s\n", R3S_status_to_string(status));
      assert(false);
    }

    printf("\n===== iteration %d =====\n", i);
    printf("Packet 1:\n%s\n", R3S_packet_to_string(p1));
    printf("Packet 2:\n%s\n", R3S_packet_to_string(p2));
  }
}
*/

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("[ERROR] Missing arguments.");
    printf("Please provide a libvig-access-out.txt file location\n");
    return 1;
  }

  char *libvig_access_out = argv[1];

  R3S_cnstrs_func cnstrs[1];
  R3S_status_t status;

  ParallelSynthesizer::Parser parser;

  parser.parse(libvig_access_out);

  for (auto &access : parser.get_accesses()) {
    std::cout << "==========================\n";
    std::cout << "id:     " << access.get_id() << '\n';
    std::cout << "device: " << access.get_device() << '\n';
    std::cout << "object: " << access.get_object() << '\n';

    for (auto &dep : access.get_dependencies()) {
      if (dep.has_valid_packet_field())
        std::cout << "pf:    " << R3S_pf_to_string(dep.get_packet_field())
                  << '\n';
    }

    std::cout << std::endl;
  }

  for (auto &raw_constraint : parser.get_raw_constraints()) {
    std::cout << "==========================\n";
    std::cout << "first:      " << raw_constraint.get_first_access_id() << '\n';
    std::cout << "second:     " << raw_constraint.get_second_access_id()
              << '\n';
    std::cout << "expression: " << raw_constraint.get_expression() << '\n';
    std::cout << std::endl;
  }

  ParallelSynthesizer::RSSConfigBuilder rss_cfg_builder(parser.get_accesses(),
                                                  parser.get_raw_constraints());

  rss_cfg_builder.build();
}
