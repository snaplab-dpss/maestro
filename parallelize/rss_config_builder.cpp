#include "logger.h"
#include "rss_config_builder.h"

#include <iostream>
#include <algorithm>
#include <map>

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
  if (constraints.size() == 0) {
    Logger::log() << "No constraints. Configuring RSS with every possible option available.";
    Logger::log() << "\n";

    for (int iopt = R3S::R3S_FIRST_OPT; iopt <= R3S::R3S_LAST_OPT; iopt++) {
      auto opt = static_cast<R3S::R3S_opt_t>(iopt);
      rss_config.add_option(opt);
      R3S::R3S_cfg_load_opt(cfg, opt);
    }
    return;
  }

  if (unique_packet_fields_dependencies.size() == 0) {
    Logger::warn()
        << "[WARNING] No dependencies on packet fields. Nothing we can do :("
        << "\n";
    return;
  }

  // the R3S library is written in C
  R3S::R3S_opt_t *opts;
  size_t opts_sz;

  R3S::R3S_opts_from_pfs(&unique_packet_fields_dependencies[0],
                    unique_packet_fields_dependencies.size(), &opts, &opts_sz);

  for (unsigned iopt = 0; iopt < opts_sz; iopt++) {
    rss_config.add_option(opts[iopt]);
    R3S::R3S_cfg_load_opt(cfg, opts[iopt]);
  }
}

void RSSConfigBuilder::load_solver_constraints_generators() {
  solver_constraints_generators.reserve(cfg->n_keys);

  // TODO: more than 1 key scenario

  solver_constraints_generators[0] = &RSSConfigBuilder::make_solver_constraints;
}

int RSSConfigBuilder::get_device_index(unsigned int device) const {
  auto it = std::find(unique_devices.begin(), unique_devices.end(), device);

  if (it != unique_devices.end())
    return std::distance(unique_devices.begin(), it);

  return -1;
}

void RSSConfigBuilder::build_rss_config() {
  R3S::R3S_key_t* keys = new R3S::R3S_key_t[cfg->n_keys]();
  R3S::R3S_status_t status;

  if (constraints.size() == 0) {
    Logger::log() << "No constraints. Generating random keys.";
    Logger::log() << "\n";

    for (unsigned i = 0; i < cfg->n_keys; i++) {
      R3S::R3S_key_rand(cfg, keys[i]);
    }

    rss_config.set_keys(keys, cfg->n_keys);
    delete[] keys;

    return;
  }

  Logger::log() << "Running the solver now. This might take a while...";
  Logger::log() << "\n";

  status = R3S::R3S_keys_fit_cnstrs(cfg, &RSSConfigBuilder::make_solver_constraints, keys);

  if (status != R3S::R3S_STATUS_SUCCESS) {
    Logger::error() << "Error fitting keys to constraints ";
    Logger::error() << "(status " << R3S_status_to_string(status) << ")";
    Logger::error() << "\n";

    delete[] keys;
    exit(1);
  }

  rss_config.set_keys(keys, cfg->n_keys);

  delete[] keys;
}

void RSSConfigBuilder::fill_unique_devices(const std::vector<LibvigAccess>& accesses) {
    for (const auto& access : accesses) {
        auto it = std::find(unique_devices.begin(), unique_devices.end(), access.get_device());

        if (it == unique_devices.end()) {
            unique_devices.push_back(access.get_device());
        }
    }

    if (unique_devices.size() == 0) {
      Logger::warn() << "No devices. No RSS configuration to generate.";
      exit(0);
    }
}

const std::vector<LibvigAccess> RSSConfigBuilder::analyze_operations_on_objects(
        const std::vector<LibvigAccess>& accesses) {
    std::vector<LibvigAccess> trimmed_accesses;
    std::map<unsigned int, bool> store_access_by_object;

    for (const auto& access : accesses) {
        if (access.get_dependencies().size() == 0)
            continue;

        const auto& object = access.get_object();
        auto store_access = store_access_by_object.find(object);

        if (store_access != store_access_by_object.end() && store_access->second) {
            trimmed_accesses.push_back(access);
            continue;
        } else if (store_access != store_access_by_object.end()) {
            continue;
        }

        auto read_op_finder = [&](const LibvigAccess& access) -> bool {
            return access.get_object() == object && access.get_operation() == LibvigAccess::Operation::READ;
        };

        auto found_read = std::find_if(accesses.begin(), accesses.end(), read_op_finder) != accesses.end();

        auto write_op_finder = [&](const LibvigAccess& access) -> bool {
            return access.get_object() == object && access.get_operation() == LibvigAccess::Operation::WRITE;
        };

        auto found_write = std::find_if(accesses.begin(), accesses.end(), write_op_finder) != accesses.end();

        if (found_read && !found_write) {
            Logger::warn() << "Reads with no writes on object ";
            Logger::warn() << object;
            Logger::warn() << "\n";

            store_access_by_object.insert({ object, false });
            continue;
        }

        store_access_by_object.insert({ object, true });
        trimmed_accesses.push_back(access);
    }

    return trimmed_accesses;
}

std::pair<R3S::R3S_packet_t, R3S::R3S_packet_t>
RSSConfigBuilder::generate_packets(unsigned device1, unsigned device2) {
  R3S::R3S_packet_t p1, p2;
  R3S::R3S_status_t status;
  R3S::R3S_packet_from_cnstrs_data_t data;

  R3S::R3S_packet_init(&p1);
  R3S::R3S_packet_init(&p2);

  R3S::R3S_packet_rand(cfg, &p1);

  data.constraints = &RSSConfigBuilder::make_solver_constraints;
  data.key_id_in   = device1;
  data.key_id_out  = device2;
  data.packet_in   = p1;

  status = R3S::R3S_packet_from_cnstrs(cfg, data, &p2);

  if (status != R3S::R3S_STATUS_SUCCESS) {
    Logger::error() << "Error generating packet from constraints ";
    Logger::error() << "(status " << R3S::R3S_status_to_string(status) << ")";
    Logger::error() << "\n";

    exit(1);
  }

  return std::make_pair(p1, p2);
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
      *((std::vector<Constraint> *)R3S::R3S_cfg_get_user_data(cfg));

  std::vector<R3S::Z3_ast> generated_constraints;
  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);

  bool constraint_incompatible_with_current_opt = false;
  for (auto &constraint : constraints) {
    auto first_device = constraint.get_first_access().get_device();
    auto second_device = constraint.get_second_access().get_device();

    if (p1.key_id != first_device || p2.key_id != second_device)
      continue;

    R3S::Z3_ast &constraint_expression = constraint.get_expression();

    for (const auto &packet_field_expr_value : constraint.get_packet_fields()) {
      PacketFieldExpression packet_dependency_expr =
          packet_field_expr_value.first;

      const std::unique_ptr<const PacketDependency>& packet_dependency_value =
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

      if (!packet_dependency_value->should_ignore() &&
          packet_dependency_value->is_rss_compatible()) {

        const auto dependency_rss_compatible = dynamic_cast<const PacketDependencyProcessed*>(packet_dependency_value.get());

        status = R3S_packet_extract_pf(cfg, target_packet,
                                     dependency_rss_compatible->get_packet_field(),
                                     &packet_field_ast);
        if (status != R3S::R3S_STATUS_SUCCESS) {
          constraint_incompatible_with_current_opt = true;
          break;
        }

        unsigned int packet_field_ast_size =
            Z3_get_bv_sort_size(ctx, Z3_get_sort(ctx, packet_field_ast));

        unsigned int high =
            packet_field_ast_size - dependency_rss_compatible->get_bytes() * 8 - 1;
        unsigned int low = high - 7;

        target_ast = Z3_mk_extract(ctx, high, low, packet_field_ast);

      }

      else if (!packet_dependency_value->should_ignore()) {
          // TODO:
          assert(false && "TODO");
      }

      else {
        target_ast = Z3_mk_bvxor(
          ctx,
          packet_dependency_expr.get_expression(),
          packet_dependency_expr.get_expression());        
      }

      constraint_expression = ast_replace(
          ctx, constraint_expression,
          packet_dependency_expr.get_expression(), target_ast);
    }

    if (constraint_incompatible_with_current_opt) {
      constraint_incompatible_with_current_opt = false;
      continue;
    }

    constraint_expression = Z3_simplify(ctx, constraint_expression);

    generated_constraints.push_back(constraint_expression);

    /*
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
    Logger::debug() << Z3_ast_to_string(ctx, constraint_expression);
    Logger::debug() << "\n";
    */
  }

  if (generated_constraints.size() == 0)
    return NULL;

  R3S::Z3_ast final_constraint;
  
  if (generated_constraints.size() > 1) {
    final_constraint = Z3_simplify(ctx, Z3_mk_and(
      ctx, generated_constraints.size(), &generated_constraints[0]));
  } else {
    final_constraint = generated_constraints[0];
  }

  Logger::debug() << "\n";
  Logger::debug() << "=================================================";
  Logger::debug() << "\n";

  Logger::debug() << "\n";
  Logger::debug() << "[Packet info]";
  Logger::debug() << "\n";
  Logger::debug() << "p1 option: " << R3S_opt_to_string(p1.loaded_opt.opt);
  Logger::debug() << "\n";
  Logger::debug() << "p1 device: " << p1.key_id;
  Logger::debug() << "\n";
  Logger::debug() << "p2 option: " << R3S_opt_to_string(p2.loaded_opt.opt);
  Logger::debug() << "\n";
  Logger::debug() << "p2 device: " << p2.key_id;
  Logger::debug() << "\n";
  Logger::debug() << "\n";

  Logger::debug() << "[Final constraint]";
  Logger::debug() << "\n";
  Logger::debug() << Z3_ast_to_string(ctx, final_constraint) << "\n";

  return final_constraint;
}

} // namespace ParallelSynthesizer
