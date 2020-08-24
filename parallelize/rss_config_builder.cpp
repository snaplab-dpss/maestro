#include "logger.h"
#include "rss_config_builder.h"

#include <iostream>
#include <algorithm>
#include <map>

namespace ParallelSynthesizer {

void RSSConfigBuilder::merge_unique_packet_field_dependencies(
    const std::vector<R3S::R3S_pf_t> &packet_fields) {
  for (const auto &packet_field : packet_fields) {
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
    Logger::log() << "No constraints. Configuring RSS with every possible "
                     "option available.";
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
                         unique_packet_fields_dependencies.size(), &opts,
                         &opts_sz);

  for (unsigned iopt = 0; iopt < opts_sz; iopt++) {
    rss_config.add_option(opts[iopt]);
    R3S::R3S_cfg_load_opt(cfg, opts[iopt]);
  }

  delete opts;
}

void RSSConfigBuilder::fill_constraints(const std::vector<LibvigAccess> &accesses) {
  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);

  auto size = accesses.size();

  for (unsigned int first_idx = 0; first_idx < size; first_idx++) {
    for (unsigned int second_idx = first_idx + 1; second_idx < size; second_idx++) {
      const auto& first = accesses[first_idx];
      const auto& second = accesses[second_idx];

      if (first.get_object() != second.get_object())
        continue;

      if (!first.has_argument(LibvigAccessArgument::Type::READ) || !second.has_argument(LibvigAccessArgument::Type::READ))
        continue;

      auto& first_read_arg = first.get_argument(LibvigAccessArgument::Type::READ);
      auto& second_read_arg = second.get_argument(LibvigAccessArgument::Type::READ);

      constraints.emplace_back(first, second, ctx);

      auto first_dependencies = first_read_arg.get_dependencies();
      auto second_dependencies = second_read_arg.get_dependencies();

      auto first_unique_packet_fields = first_dependencies.get_unique_packet_fields();
      auto second_unique_packet_fields = second_dependencies.get_unique_packet_fields();

      merge_unique_packet_field_dependencies(first_unique_packet_fields);
      merge_unique_packet_field_dependencies(second_unique_packet_fields);
    }
  }
}

void RSSConfigBuilder::analyse_constraints() {
  std::vector<Constraint> filtered_constraints;

  for (const auto& constraint : constraints) {
    if (constraint.get_packet_dependencies_expressions().size())
      filtered_constraints.push_back(constraint);
  }

  constraints = filtered_constraints;
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
  R3S::R3S_key_t *keys = new R3S::R3S_key_t[cfg->n_keys]();
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

  status = R3S::R3S_keys_fit_cnstrs(
      cfg, &RSSConfigBuilder::make_solver_constraints, keys);

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

void RSSConfigBuilder::fill_unique_devices(
    const std::vector<LibvigAccess> &accesses) {
  for (const auto &access : accesses) {
    auto src_device = access.get_src_device();
    auto src_it =
        std::find(unique_devices.begin(), unique_devices.end(), src_device);

    if (src_it == unique_devices.end()) {
      unique_devices.push_back(src_device);
    }

    if (!access.is_dst_device_set())
      continue;

    auto dst_device = access.get_dst_device();
    auto dst_it =
        std::find(unique_devices.begin(), unique_devices.end(), dst_device);

    if (dst_it == unique_devices.end()) {
      unique_devices.push_back(dst_device);
    }
  }

  if (unique_devices.size() == 0) {
    Logger::warn() << "No devices. No RSS configuration to generate." << "\n";
    exit(0);
  }
}

std::vector<LibvigAccess> RSSConfigBuilder::filter_reads_without_writes_on_objects(
    const std::vector<LibvigAccess> &accesses) {
  std::vector<LibvigAccess> trimmed_accesses;
  std::map<unsigned int, bool> access_by_object;

  for (const auto &access : accesses) {
    const auto &object = access.get_object();
    auto store_access = access_by_object.find(object);

    if (store_access != access_by_object.end() && store_access->second) {
      trimmed_accesses.push_back(access);
      continue;
    } else if (store_access != access_by_object.end()) {
      continue;
    }

    auto read_op_finder = [&](const LibvigAccess & access)->bool {
      if (access.get_object() != object)
        return false;

      return access.get_operation() == LibvigAccess::Operation::READ ||
             access.get_operation() == LibvigAccess::Operation::VERIFY;
    };

    auto found_read = std::find_if(accesses.begin(), accesses.end(),
                                   read_op_finder) != accesses.end();

    auto write_op_finder = [&](const LibvigAccess & access)->bool {
      if (access.get_object() != object)
        return false;

      return access.get_operation() == LibvigAccess::Operation::WRITE ||
             access.get_operation() == LibvigAccess::Operation::CREATE;
    };

    auto found_write = std::find_if(accesses.begin(), accesses.end(),
                                    write_op_finder) != accesses.end();

    if (found_read && !found_write) {
      Logger::warn() << "Reads with no writes on object ";
      Logger::warn() << object;
      Logger::warn() << "\n";

      access_by_object.insert({ object, false });
      continue;
    }

    access_by_object.insert({ object, true });
    trimmed_accesses.push_back(access);
  }

  return trimmed_accesses;
}

bool RSSConfigBuilder::is_write_modifying(const std::vector<LibvigAccess>&cp, LibvigAccess write) {
  assert(write.has_argument(LibvigAccessArgument::Type::WRITE));

  auto is_read_access_in_same_data_structure = [&](const LibvigAccess& access) -> bool {
    auto write_data_structure = write.get_metadata().get_data_structure();
    auto access_data_structure = access.get_metadata().get_data_structure();

    if (write_data_structure != access_data_structure)
      return false;

    return access.get_operation() == LibvigAccess::Operation::READ;
  };

  auto read_it = std::find_if(cp.begin(), cp.end(), is_read_access_in_same_data_structure);

  if (read_it == cp.end())
    return true;

  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);

  auto read_arg = read_it->get_argument(LibvigAccessArgument::Type::RESULT);
  auto write_arg = write.get_argument(LibvigAccessArgument::Type::WRITE);

  auto result_expr = Constraint::parse_expr(ctx, read_arg.get_expression());
  auto write_expr = Constraint::parse_expr(ctx, write_arg.get_expression());

  return !R3S::Z3_is_eq_ast(ctx, write_expr, result_expr);
}

bool RSSConfigBuilder::are_call_paths_equivalent(const std::vector<LibvigAccess>& cp1, const std::vector<LibvigAccess>& cp2) {
  assert(cp1.size() && cp2.size());

  // Compare destination devices,
  // i.e., is the packet always dropped
  // or always sent to the same device?

  auto& access = cp1[0];
  for (unsigned int i = 0; i < std::max(cp1.size(), cp2.size()); i++) {
    if (i < cp1.size() && !access.are_dst_devices_equal(cp1[i])) {
      return false;
    }

    if (i < cp2.size() && !access.are_dst_devices_equal(cp2[i])) {
      return false;
    }
  }

  auto write_accesses_1 = cp1;
  auto write_accesses_2 = cp2;

  auto is_not_write_access = [](const LibvigAccess& access) -> bool {
    return access.get_operation() != LibvigAccess::Operation::WRITE;
  };

  write_accesses_1.erase(std::remove_if(write_accesses_1.begin(), write_accesses_1.end(), is_not_write_access), write_accesses_1.end());
  write_accesses_2.erase(std::remove_if(write_accesses_2.begin(), write_accesses_2.end(), is_not_write_access), write_accesses_2.end());

  for (const auto& access : write_accesses_1) {
    if (is_write_modifying(cp1, access))
      return false;
  }

  for (const auto& access : write_accesses_2) {
    if (is_write_modifying(cp2, access))
      return false;
  }

  return true;
}

void RSSConfigBuilder::poison_packet_fields(std::map< unsigned int, std::vector<R3S::R3S_pf_t> >& poisoned_packet_fields) {
  bool changed = false;

  auto get_prohibited_packet_dependent_pdes = [&](const Constraint& constraint) -> std::vector<const PacketDependenciesExpression*> {
    std::vector<const PacketDependenciesExpression*> pdes;

    for (const auto& device_prohibited_packet_fields_pair : poisoned_packet_fields) {
      const auto& poisoned_device = device_prohibited_packet_fields_pair.first;
      const auto& poisoned_packet_fields = device_prohibited_packet_fields_pair.second;

      if (constraint.get_first_access().get_src_device() != poisoned_device &&
          constraint.get_second_access().get_src_device() != poisoned_device) {
        return pdes;
      }

      for (const auto& prohibited_packet_field : poisoned_packet_fields) {
        const auto pde = constraint.get_packet_dependency_expression(poisoned_device, prohibited_packet_field);

        if (pde) {
          pdes.push_back(pde);
        }
      }
    }

    return pdes;
  };

  for (const auto& constraint : constraints) {
    auto prohibited_packet_dependent_pdes = get_prohibited_packet_dependent_pdes(constraint);
    if (constraint.get_first_access().get_src_device() == 0 && constraint.get_first_access().get_src_device() == constraint.get_second_access().get_src_device()) {
      Logger::debug() << constraint << "\n";
    }

    for (const auto& prohibited_packet_dependent_pde : prohibited_packet_dependent_pdes) {
      R3S::Z3_ast associated_expression = RSSConfigBuilder::ast_equal_association(
            constraint.get_context(),
            constraint.get_expression(), prohibited_packet_dependent_pde->get_expression());

      const auto associated_packet_dependency_expression = constraint.get_packet_dependencies_expression(associated_expression);

      if (associated_packet_dependency_expression == nullptr) {
        continue;
      }

      Logger::warn() << *associated_packet_dependency_expression << "\n";

      const auto& associated_packet_chunk_id = associated_packet_dependency_expression->get_packet_chunks_id();
      const auto& constraint_packet_chunks_ids = constraint.get_packet_chunks_ids();

      unsigned int associated_device;

      if (associated_packet_chunk_id == constraint_packet_chunks_ids.first) {
        associated_device = constraint.get_first_access().get_src_device();
      }

      else if (associated_packet_chunk_id == constraint_packet_chunks_ids.second) {
        associated_device = constraint.get_second_access().get_src_device();
      }

      else {
        assert(false && "this should not happen");
      }

      auto packet_fields = associated_packet_dependency_expression->get_associated_dependencies_packet_fields();
      auto stored = poisoned_packet_fields[associated_device];

      for (const auto& packet_field : packet_fields) {
        auto found_it = std::find(stored.begin(), stored.end(), packet_field);
        if (found_it == stored.end()) {
          stored.push_back(packet_field);
          changed = true;
        }

        poisoned_packet_fields[associated_device] = stored;
      }
    }
  }


  if (changed) {
    poison_packet_fields(poisoned_packet_fields);
  }
}

void RSSConfigBuilder::remove_constraints_with_prohibited_packet_fields(unsigned int device, std::vector<R3S::R3S_pf_t> prohibited_packet_fields) {

  std::map< unsigned int, std::vector<R3S::R3S_pf_t> > poisoned_packet_fields_per_device;
  poisoned_packet_fields_per_device[device] = prohibited_packet_fields;

  poison_packet_fields(poisoned_packet_fields_per_device);

  for (const auto& device_prohibited_packet_fields_pair : poisoned_packet_fields_per_device) {
    Logger::warn() << "\n";
    Logger::warn() << "In device " << device_prohibited_packet_fields_pair.first << ":" << "\n";
    for (const auto& pf : device_prohibited_packet_fields_pair.second) {
      Logger::warn() << "  -> prohibited packet fields " << R3S::R3S_pf_to_string(pf) << "\n";
    }
  }

  exit(0);

  auto prohibited_packet_dependent = [&](const Constraint& constraint) -> bool {
    for (const auto& device_prohibited_packet_fields_pair : poisoned_packet_fields_per_device) {
      const auto& poisoned_device = device_prohibited_packet_fields_pair.first;
      const auto& poisoned_packet_fields = device_prohibited_packet_fields_pair.second;

      if (constraint.get_first_access().get_src_device() != poisoned_device &&
          constraint.get_second_access().get_src_device() != poisoned_device) {
        return false;
      }

      for (const auto& prohibited_packet_field : poisoned_packet_fields) {
        if (constraint.has_packet_field(prohibited_packet_field, poisoned_device)) {
          return true;
        }
      }
    }

    return false;
  };

  Logger::debug () << "before " << constraints.size() << "\n";
  constraints.erase(std::remove_if(constraints.begin(), constraints.end(), prohibited_packet_dependent), constraints.end());
  Logger::debug () << "after " << constraints.size() << "\n";

  for (const auto& constraint : constraints) {
    Logger::debug() << constraint << "\n";
  }

  exit(0);


}

void RSSConfigBuilder::verify_dchain_correctness(const std::vector<LibvigAccess>& accesses, const LibvigAccess& dchain_verify) {
  assert(dchain_verify.get_operation() == LibvigAccess::Operation::VERIFY);

  auto read_arg = dchain_verify.get_argument(LibvigAccessArgument::Type::READ);
  auto dependencies = read_arg.get_dependencies();
  auto packet_fields = dependencies.get_unique_packet_fields();

  if (packet_fields.size() == 0)
    return;

  std::map< std::string, std::vector<LibvigAccess> > call_paths;
  for (const auto& access : accesses) {
    auto call_path = access.get_metadata().get_file();
    call_paths[call_path].push_back(access);
  }

  std::map< std::string, std::vector<LibvigAccess> > failed_verifications_call_paths;
  std::map< std::string, std::vector<LibvigAccess> > successful_verifications_call_paths;
  std::map< std::string, std::vector<LibvigAccess> > successful_verifications_failed_constraints_call_paths;

  auto is_failed_verification = [](const LibvigAccess& access) -> bool {
    return access.get_metadata().get_interface() == "dchain_is_index_allocated" &&
        access.is_success_set() && access.get_success() == 0;
  };

  auto is_successful_verification = [](const LibvigAccess& access) -> bool {
    return access.get_metadata().get_interface() == "dchain_is_index_allocated" &&
        access.is_success_set() && access.get_success() != 0;
  };

  auto has_constraints_with_other_call_path = [&](const LibvigAccess& access) -> bool {
    const auto& metadata = access.get_metadata();
    const auto& call_path_fname = metadata.get_file();

    auto found_it = std::find_if(
          call_paths_constraints.begin(),
          call_paths_constraints.end(),
          [&](const CallPathsConstraint& call_path_constraint) -> bool {
            return call_path_fname == call_path_constraint.get_call_path_info(CallPathInfo::Type::SOURCE).get_call_path();
          });

    return found_it != call_paths_constraints.end();
  };

  for (auto call_path : call_paths) {
    auto has_failed_verification_it = std::find_if(call_path.second.begin(), call_path.second.end(), is_failed_verification);
    auto has_failed_verification = has_failed_verification_it != call_path.second.end();

    if (has_failed_verification) {
      failed_verifications_call_paths[call_path.first] = call_path.second;
      continue;
    }

    auto has_successful_verification_it = std::find_if(call_path.second.begin(), call_path.second.end(), is_successful_verification);
    auto has_successful_verification = has_successful_verification_it != call_path.second.end();

    auto has_constraints_it = std::find_if(call_path.second.begin(), call_path.second.end(), has_constraints_with_other_call_path);
    auto has_constraints = has_constraints_it != call_path.second.end();

    if (has_successful_verification && has_constraints) {
      successful_verifications_call_paths[call_path.first] = call_path.second;
    }

    else if (has_successful_verification) {
      successful_verifications_failed_constraints_call_paths[call_path.first] = call_path.second;
    }
  }

  auto equivalent_failures = true;
  for (const auto& failed_verification_pair : failed_verifications_call_paths) {
    for (const auto& successful_verifications_failed_constraints_pair : successful_verifications_failed_constraints_call_paths) {
      equivalent_failures = equivalent_failures && are_call_paths_equivalent(
            failed_verification_pair.second,
            successful_verifications_failed_constraints_pair.second);

      if (!equivalent_failures)
        break;
    }

    if (!equivalent_failures)
      break;
  }

  if (equivalent_failures) {
    remove_constraints_with_prohibited_packet_fields(dchain_verify.get_src_device(), packet_fields);
    return;
  }

  Logger::error() << "Indexes generated by a dchain are being interpreted as packet fields." << "\n";
  Logger::error() << "The generation of these indexes doesn't take into consideration the RSS hash process." << "\n";
  Logger::error() << "Because of this, it is impossible to correctly send packets to the same cores where these indexes were generated." << "\n";
  Logger::error() << "\n";
  Logger::error() << "Parallel incompatible access:" << "\n";
  Logger::error() << dchain_verify << "\n";

  exit(0);
}

void RSSConfigBuilder::analyse_dchain_interpretations(const std::vector<LibvigAccess>& accesses) {
  for (const auto &access : accesses) {
    if (access.get_operation() != LibvigAccess::Operation::VERIFY)
      continue;

    verify_dchain_correctness(accesses, access);
  }
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
  data.key_id_in = device1;
  data.key_id_out = device2;
  data.packet_in = p1;

  status = R3S::R3S_packet_from_cnstrs(cfg, data, &p2);

  if (status != R3S::R3S_STATUS_SUCCESS) {
    Logger::error() << "Error generating packet from constraints ";
    Logger::error() << "(status " << R3S::R3S_status_to_string(status) << ")";
    Logger::error() << "\n";

    exit(1);
  }

  return std::make_pair(p1, p2);
}

// should ask the solver
R3S::Z3_ast RSSConfigBuilder::ast_equal_association(R3S::Z3_context ctx, R3S::Z3_ast root,
                                                    R3S::Z3_ast target) {
  R3S::Z3_ast associated;

  if (Z3_get_ast_kind(ctx, root) != R3S::Z3_APP_AST)
    return nullptr;

  R3S::Z3_app app = Z3_to_app(ctx, root);
  unsigned num_fields = Z3_get_app_num_args(ctx, app);

  for (unsigned i = 0; i < num_fields; i++) {
    if (Z3_is_eq_ast(ctx, Z3_get_app_arg(ctx, app, i), target)) {
      assert(num_fields == 2);
      associated = Z3_get_app_arg(ctx, app, num_fields - i - 1);
      return associated;
    }

    associated = ast_equal_association(ctx, Z3_get_app_arg(ctx, app, i), target);

    if (associated) {
      return associated;
    }
  }

  return nullptr;
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

std::vector<Constraint> RSSConfigBuilder::get_constraints_between_devices(std::vector<Constraint> constraints, unsigned int p1_device, unsigned int p2_device) {
  auto filter = [&](const Constraint& constraint) -> bool {
    auto first_device  = constraint.get_first_access().get_src_device();
    auto second_device = constraint.get_second_access().get_src_device();

    return p1_device != first_device || p2_device != second_device;
  };

  constraints.erase(std::remove_if(constraints.begin(), constraints.end(), filter), constraints.end());

  return constraints;
}

R3S::Z3_ast RSSConfigBuilder::constraint_to_solver_input(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2, const Constraint& constraint) {
  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);
  R3S::Z3_ast constraint_expression = constraint.get_expression();

  for (const auto& packet_dependency_expression : constraint.get_packet_dependencies_expressions()) {
    auto expression = packet_dependency_expression.get_expression();
    R3S::Z3_ast target_ast;

    R3S::R3S_packet_ast_t target_packet;

    if (packet_dependency_expression.get_packet_chunks_id() == constraint.get_packet_chunks_ids().first) {
      target_packet = p1;
    } else if (packet_dependency_expression.get_packet_chunks_id() == constraint.get_packet_chunks_ids().second) {
      target_packet = p2;
    } else {
      assert(false && "Invalid target packet: chunk id in packet dependency expression wrongly associated with constraint");
    }

    auto compatible_dependency = packet_dependency_expression.get_dependency_compatible_with_packet(cfg, target_packet);

    if (compatible_dependency) {
      R3S::R3S_status_t status;

      auto processed_dependency = dynamic_cast<PacketDependencyProcessed *>(compatible_dependency.get());
      auto packet_field = processed_dependency->get_packet_field();

      R3S::Z3_ast packet_field_ast;
      status = R3S_packet_extract_pf(cfg, target_packet, packet_field, &packet_field_ast);
      assert(status == R3S::R3S_STATUS_SUCCESS);

      auto packet_field_sort = Z3_get_sort(ctx, packet_field_ast);
      auto packet_field_size = Z3_get_bv_sort_size(ctx, packet_field_sort);

      auto high = packet_field_size - processed_dependency->get_bytes() * 8 - 1;
      auto low = high - 7;

      target_ast = Z3_mk_extract(ctx, high, low, packet_field_ast);
    }

    else if (packet_dependency_expression.get_associated_dependencies()[0]->should_ignore()) {
      auto associated_dependencies = packet_dependency_expression.get_associated_dependencies();
      assert(associated_dependencies.size() == 1);
      target_ast = Z3_mk_bvxor(ctx, expression, expression);
    }

    else {
      return nullptr;
    }

    constraint_expression = ast_replace(ctx, constraint_expression, expression, target_ast);
  }

  return Z3_simplify(ctx, constraint_expression);
}

R3S::Z3_ast RSSConfigBuilder::make_solver_constraints(
    R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2) {

  auto constraints = *((std::vector<Constraint> *)R3S::R3S_cfg_get_user_data(cfg));
  auto ctx = R3S::R3S_cfg_get_z3_context(cfg);

  std::vector<R3S::Z3_ast> generated_constraints;
  R3S::Z3_ast final_constraint;


  auto filtered_constraints = get_constraints_between_devices(constraints, p1.key_id, p2.key_id);

  for (auto &constraint : filtered_constraints) {
    auto constraint_expression = constraint_to_solver_input(cfg, p1, p2, constraint);

    if (!constraint_expression)
      continue;

    generated_constraints.push_back(constraint_expression);
  }

  if (generated_constraints.size() == 0)
    return NULL;

  if (generated_constraints.size() > 1) {
    final_constraint =
        R3S::Z3_simplify(ctx, R3S::Z3_mk_and(ctx, generated_constraints.size(),
                                   &generated_constraints[0]));
  } else {
    final_constraint = generated_constraints[0];
  }

  Logger::debug() << "\n";
  Logger::debug() << "=================================================";
  Logger::debug() << "\n";

  Logger::debug() << "\n";
  Logger::debug() << "[Packet info]";
  Logger::debug() << "\n";
  Logger::debug() << "p1 option: " << R3S::R3S_opt_to_string(p1.loaded_opt.opt);
  Logger::debug() << "\n";
  Logger::debug() << "p1 device: " << p1.key_id;
  Logger::debug() << "\n";
  Logger::debug() << "p2 option: " << R3S::R3S_opt_to_string(p2.loaded_opt.opt);
  Logger::debug() << "\n";
  Logger::debug() << "p2 device: " << p2.key_id;
  Logger::debug() << "\n";
  Logger::debug() << "\n";

  Logger::debug() << "[Final constraint]";
  Logger::debug() << "\n";
  Logger::debug() << R3S::Z3_ast_to_string(ctx, final_constraint) << "\n";

  return final_constraint;
}

} // namespace ParallelSynthesizer
