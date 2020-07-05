#include "logger.h"
#include "rss_config_builder.h"

#include <iostream>
#include <algorithm>

namespace ParallelSynthesizer {

void RSSConfigBuilder::merge_unique_packet_field_dependencies(
    const std::vector<R3S::R3S_pf_t> &packet_fields) {
  for (const auto& packet_field : packet_fields) {
    auto found_it =
        std::find(unique_packet_fields_dependencies.begin(),
                  unique_packet_fields_dependencies.end(), packet_field);

    if (found_it != unique_packet_fields_dependencies.end())
      continue;

    unique_packet_fields_dependencies.push_back(packet_field);
  }
}

bool RSSConfigBuilder::is_access_pair_already_stored(
    const std::pair<LibvigAccess, LibvigAccess> &pair) {
  for (const auto &stored_pair : unique_access_pairs) {
    if (!LibvigAccess::content_equal(stored_pair.first, pair.first))
      continue;
    if (!LibvigAccess::content_equal(stored_pair.second, pair.second))
      continue;

    return true;
  }

  return false;
}

void RSSConfigBuilder::load_rss_config_options() {
  for (const auto &option : rss_config.options)
    R3S_cfg_load_opt(&cfg, option);

  Logger::debug() << "\nR3S configuration:"
                  << "\n";
  Logger::debug() << R3S_cfg_to_string(cfg) << "\n";
}

void RSSConfigBuilder::find_compatible_rss_config_options() {
  if (unique_packet_fields_dependencies.size() == 0) {
    Logger::warn()
        << "[WARNING] No dependencies on packet fields. Nothing we can do :("
        << "\n";
    return;
  }

  // the R3S library is written in C
  R3S::R3S_opt_t *opts;
  size_t opts_sz;

  R3S_opts_from_pfs(&unique_packet_fields_dependencies[0],
                    unique_packet_fields_dependencies.size(), &opts, &opts_sz);

  rss_config.options = std::vector<R3S::R3S_opt_t>(opts, opts + opts_sz);
}

void RSSConfigBuilder::load_solver_constraints_generators() {
  solver_constraints_generators.reserve(cfg.n_keys);

  // TODO: more than 1 key scenario

  solver_constraints_generators[0] = &RSSConfigBuilder::make_solver_constraints;
}

void RSSConfigBuilder::build() {
  R3S::R3S_key_t &key = rss_config.key;
  R3S::R3S_status_t status;
  std::vector<R3S::R3S_cnstrs_func> solver_constraints;

  solver_constraints.push_back(&RSSConfigBuilder::make_solver_constraints);

  Logger::log() << "Running the solver now. This might take a while...";
  Logger::log() << "\n";

  status = R3S::R3S_keys_fit_cnstrs(cfg, &solver_constraints[0], &key);

  if (status != R3S::R3S_STATUS_SUCCESS) {
    Logger::error() << "Error fitting keys to constraints ";
    Logger::error() << "(status " << R3S_status_to_string(status) << ")";
    Logger::error() << "\n";

    exit(1);
  }
}

std::pair<R3S::R3S_packet_t, R3S::R3S_packet_t>
RSSConfigBuilder::generate_packets() {
  R3S::R3S_packet_t p1, p2;
  R3S::R3S_status_t status;

  R3S_packet_rand(cfg, &p1);

  if ((status = R3S_packet_from_cnstrs(
           cfg, p1, &RSSConfigBuilder::make_solver_constraints, &p2)) !=
      R3S::R3S_STATUS_SUCCESS) {
    Logger::error() << "Error generating packet from constraints ";
    Logger::error() << "(status " << R3S_status_to_string(status) << ")";
    Logger::error() << "\n";

    exit(1);
  }

  return std::pair<R3S::R3S_packet_t, R3S::R3S_packet_t>(p1, p2);
}

R3S::Z3_ast RSSConfigBuilder::ast_replace(R3S::Z3_context ctx, R3S::Z3_ast root,
                                          R3S::Z3_ast target, R3S::Z3_ast dst) {
  if (Z3_get_ast_kind(ctx, root) != R3S::Z3_APP_AST)
    return root;

  R3S::Z3_app app = Z3_to_app(ctx, root);
  unsigned num_fields = Z3_get_app_num_args(ctx, app);
  R3S::Z3_ast *updated_args =
      (R3S::Z3_ast *)malloc(sizeof(R3S::Z3_ast) * num_fields);

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

R3S::Z3_ast RSSConfigBuilder::make_solver_constraints(
    R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2) {

  std::vector<Constraint> constraints =
      *((std::vector<Constraint> *)R3S_get_user_data(cfg));

  std::vector<R3S::Z3_ast> generated_constraints;

  Logger::debug() << "\n";
  Logger::debug() << "*************************************************";
  Logger::debug() << "\n";
  Logger::debug() << "*            Constraints generator              *";
  Logger::debug() << "\n";
  Logger::debug() << "*************************************************";
  Logger::debug() << "\n";

  bool constraint_incompatible_with_current_opt = false;
  for (auto &constraint : constraints) {
    R3S::Z3_ast &constraint_expression = constraint.get_expression();

    for (const auto &packet_field_expr_value : constraint.get_packet_fields()) {
      PacketFieldExpression packet_dependency_expr =
          packet_field_expr_value.first;
      PacketDependencyProcessed packet_dependency_value =
          packet_field_expr_value.second;

      // TODO: error handling if is neither equal to first or second
      R3S::R3S_packet_ast_t target_packet =
          (packet_dependency_expr.get_packet_chunks_id() ==
           constraint.get_packet_chunks_ids_pair().first)
              ? p1
              : p2;

      R3S::Z3_ast packet_field_ast;
      R3S::R3S_status_t status;
      R3S::Z3_ast target_ast;

      if (!packet_dependency_value.should_ignore()) {
        status = R3S_packet_extract_pf(cfg, target_packet,
                                     packet_dependency_value.get_packet_field(),
                                     &packet_field_ast);
        if (status != R3S::R3S_STATUS_SUCCESS) {
          constraint_incompatible_with_current_opt = true;
          break;
        }

        unsigned int packet_field_ast_size =
            Z3_get_bv_sort_size(cfg.ctx, Z3_get_sort(cfg.ctx, packet_field_ast));

        unsigned int high =
            packet_field_ast_size - packet_dependency_value.get_bytes() * 8 - 1;
        unsigned int low = high - 7;

        target_ast = Z3_mk_extract(cfg.ctx, high, low, packet_field_ast);
      }

      else {
        target_ast = Z3_mk_bvxor(
          cfg.ctx,
          packet_dependency_expr.get_expression(),
          packet_dependency_expr.get_expression());        
      }

      constraint_expression = ast_replace(
          cfg.ctx, constraint_expression,
          packet_dependency_expr.get_expression(), target_ast);
    }

    if (constraint_incompatible_with_current_opt) {
      constraint_incompatible_with_current_opt = false;
      continue;
    }

    constraint_expression = Z3_simplify(cfg.ctx, constraint_expression);

    generated_constraints.push_back(constraint_expression);

    Logger::debug() << "\n";
    Logger::debug() << "================================================="
                    << "\n";

    Logger::debug() << "\n";
    Logger::debug() << "[Packet options]"
                    << "\n";
    Logger::debug() << "p1 option: " << R3S_opt_to_string(p1.loaded_opt.opt)
                    << "\n";
    Logger::debug() << "p2 option: " << R3S_opt_to_string(p2.loaded_opt.opt)
                    << "\n";

    Logger::debug() << "\n";
    Logger::debug() << "[Access]"
                    << "\n";
    Logger::debug() << "first:  ";
    Logger::debug() << constraint.get_first_access().get_id() << " (id) ";
    Logger::debug() << constraint.get_first_access().get_device()
                    << " (device) ";
    Logger::debug() << constraint.get_first_access().get_object()
                    << " (object) ";

    for (const auto &packet_field_expr_value : constraint.get_packet_fields()) {
      PacketFieldExpression packet_dependency_expr =
          packet_field_expr_value.first;
      if (packet_dependency_expr.get_packet_chunks_id() != constraint.get_packet_chunks_ids_pair().first)
        continue;
      PacketDependencyProcessed packet_dependency_value =
          packet_field_expr_value.second;
      if (packet_dependency_value.should_ignore()) continue;

      Logger::debug() << " " << R3S_pf_to_string(packet_dependency_value.get_packet_field());
    }
    Logger::debug() << "\n";

    Logger::debug() << "second: ";
    Logger::debug() << constraint.get_second_access().get_id() << " (id) ";
    Logger::debug() << constraint.get_second_access().get_device()
                    << " (device) ";
    Logger::debug() << constraint.get_second_access().get_object()
                    << " (object) ";

    for (const auto &packet_field_expr_value : constraint.get_packet_fields()) {
      PacketFieldExpression packet_dependency_expr =
          packet_field_expr_value.first;
      if (packet_dependency_expr.get_packet_chunks_id() != constraint.get_packet_chunks_ids_pair().second)
        continue;
      PacketDependencyProcessed packet_dependency_value =
          packet_field_expr_value.second;
      if (packet_dependency_value.should_ignore()) continue;

      Logger::debug() << " " << R3S_pf_to_string(packet_dependency_value.get_packet_field());
    }
    Logger::debug() << "\n";
    Logger::debug() << "\n";
    Logger::debug() << "[Constraint]"
                    << "\n";
    Logger::debug() << Z3_ast_to_string(cfg.ctx, constraint_expression);
    Logger::debug() << "\n";
  }

  R3S::Z3_ast final_constraint;
  
  if (generated_constraints.size() > 1) {
    final_constraint = Z3_simplify(cfg.ctx, Z3_mk_and(
      cfg.ctx, generated_constraints.size(), &generated_constraints[0]));
  } else if (generated_constraints.size() == 1) {
    final_constraint = generated_constraints[0];
  } else {
    final_constraint = NULL;
  }

  Logger::debug() << "[Final constraint]";
  Logger::debug() << "\n";
  Logger::debug() << Z3_ast_to_string(cfg.ctx, final_constraint) << "\n";

  return final_constraint;
}

} // namespace ParallelSynthesizer
