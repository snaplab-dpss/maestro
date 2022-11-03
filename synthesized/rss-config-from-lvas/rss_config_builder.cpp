#include "logger.h"
#include "rss_config_builder.h"

#include <iostream>
#include <algorithm>
#include <map>
#include <array>
#include <thread>

namespace ParallelSynthesizer {

void RSSConfigBuilder::merge_unique_packet_field_dependencies(
    const std::vector<R3S::R3S_pf_t> &packet_fields) {
  for (const auto &packet_field : packet_fields) {
    auto found_it =
        std::find(unique_packet_fields_dependencies.begin(),
                  unique_packet_fields_dependencies.end(), packet_field);

    if (found_it != unique_packet_fields_dependencies.end()) continue;

    unique_packet_fields_dependencies.push_back(packet_field);
  }
}

bool RSSConfigBuilder::is_access_pair_already_stored(
    const std::pair<LibvigAccess, LibvigAccess> &pair) {
  for (const auto &stored_pair : unique_access_pairs) {
    if (!LibvigAccess::content_equal(stored_pair.first, pair.first)) continue;
    if (!LibvigAccess::content_equal(stored_pair.second, pair.second)) continue;

    return true;
  }

  return false;
}

void RSSConfigBuilder::load_rss_config_options() {
  const auto n_threads = std::thread::hardware_concurrency();

  R3S::R3S_cfg_set_number_of_keys(cfg, unique_devices.size());
  R3S::R3S_cfg_set_number_of_processes(cfg, n_threads / 2);

  if (libvig_access_constraints.size() == 0) {
    Logger::debug() << "No constraints. Configuring RSS with every possible "
                       "option available.";
    Logger::debug() << "\n";

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

  delete[] opts;
}

void RSSConfigBuilder::filter_constraints() {
  std::vector<R3S::R3S_pf_t> pfs = unique_packet_fields_dependencies;

  // get the smallest set of pfs
  // check only for the first device
  for (auto constraint : constraints) {
    auto device = constraint->get_devices().first;
    auto saved_constraint_pfs = constraint->get_packet_fields(device);

    if (saved_constraint_pfs.size() == 0 ||
        saved_constraint_pfs.size() >= pfs.size()) {
    continue;
    }

    bool not_found = false;
    for (auto pf : saved_constraint_pfs) {
    auto found_it = std::find(pfs.begin(), pfs.end(), pf);
    if (found_it == pfs.end()) {
        not_found = true;
        break;
    }
    }

    if (not_found) {
    return;
    }

    pfs.clear();
    pfs = saved_constraint_pfs;
  }
    
  if (pfs.size() == unique_packet_fields_dependencies.size()) {
    return;
  }

  // There are some constraints that use a smaller number of PFs.
  constraints.erase(
      std::remove_if(constraints.begin(), constraints.end(),
                     [&](const std::shared_ptr<Constraint> &constraint) {
      auto device = constraint->get_devices().first;
      auto saved_constraint_pfs = constraint->get_packet_fields(device);
      if (saved_constraint_pfs.size() != pfs.size()) {
          return true;
      }

      auto eq = std::equal(saved_constraint_pfs.begin(),
                          saved_constraint_pfs.end(), pfs.begin());
      if (!eq) {
          return true;
      }

      return false;
      }),
      constraints.end());

  // TODO: we should update the R3S configuration
}

void RSSConfigBuilder::fill_libvig_access_constraints(
    const std::vector<LibvigAccess> &accesses) {
  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);

  auto size = accesses.size();

  for (unsigned int first_idx = 0; first_idx < size; first_idx++) {
    for (unsigned int second_idx = first_idx + 1; second_idx < size;
         second_idx++) {
      const auto &first = accesses[first_idx];
      const auto &second = accesses[second_idx];

      if (first.get_object() != second.get_object()) {
        continue;
      }

      if (first.get_metadata().get_file() == second.get_metadata().get_file()) {
        continue;
      }

      if (!first.has_argument(LibvigAccessArgument::Type::READ) ||
          !second.has_argument(LibvigAccessArgument::Type::READ)) {
        continue;
      }

      auto &first_read_arg =
          first.get_argument(LibvigAccessArgument::Type::READ);
      auto &second_read_arg =
          second.get_argument(LibvigAccessArgument::Type::READ);

      libvig_access_constraints.emplace_back(first, second, ctx);

      auto first_dependencies = first_read_arg.get_dependencies();
      auto second_dependencies = second_read_arg.get_dependencies();

      auto first_unique_packet_fields =
          first_dependencies.get_unique_packet_fields();
      auto second_unique_packet_fields =
          second_dependencies.get_unique_packet_fields();

      merge_unique_packet_field_dependencies(first_unique_packet_fields);
      merge_unique_packet_field_dependencies(second_unique_packet_fields);
    }
  }
}

std::vector<R3S::R3S_pf_t> interset_packet_fields(
    std::vector<R3S::R3S_pf_t> pf1, std::vector<R3S::R3S_pf_t> pf2) {
  std::vector<R3S::R3S_pf_t> result;

  std::sort(pf1.begin(), pf1.end());
  std::sort(pf2.begin(), pf2.end());

  for (const auto &pf : pf1) {
    auto found_it = std::find(pf2.begin(), pf2.end(), pf);

    if (found_it == pf2.end()) {
      continue;
    }

    auto stored_it = std::find(result.begin(), result.end(), pf);

    if (stored_it != result.end()) {
      continue;
    }

    result.push_back(pf);
  }

  return result;
}

bool analyse_constraint(Constraint *constraint) {
  assert(constraint);

  auto non_packet_dependencies_expression =
      constraint->get_non_packet_dependencies_expressions();
  auto packet_dependencies_expression =
      constraint->get_packet_dependencies_expressions();

  if (non_packet_dependencies_expression.size() &&
      packet_dependencies_expression.size()) {
    Logger::error() << "Constraint with unknown dependency."
                    << "\n";
    Logger::error() << constraint << "\n";
    exit(0);
  }

  if (non_packet_dependencies_expression.size()) {
    for (const auto &npde : non_packet_dependencies_expression) {
      auto symbol = npde.get_symbol();

      auto is_new_index = symbol.find("new_index");
      auto is_allocated_index = symbol.find("allocated_index");

      if (is_new_index != std::string::npos) {
        continue;
      }

      if (is_allocated_index != std::string::npos) {
        continue;
      }

      Logger::error() << "Constraint with unknown dependency."
                      << "\n";
      Logger::error() << constraint << "\n";
      exit(0);
    }
  }

  if (packet_dependencies_expression.size() == 0) {
    return false;
  }

  return true;
}

void RSSConfigBuilder::generate_solver_constraints() {
  std::map<unsigned int, std::vector<R3S::R3S_pf_t> > packet_fields_per_device;

  for (auto call_path_constraint : call_paths_constraints) {
    const auto &source =
        call_path_constraint.get_call_path_info(CallPathInfo::Type::SOURCE);
    const auto &pair =
        call_path_constraint.get_call_path_info(CallPathInfo::Type::PAIR);

    const auto &source_call_path = source.get_call_path();
    const auto &pair_call_path = pair.get_call_path();

    assert(device_per_call_path.find(source_call_path) !=
           device_per_call_path.end());
    assert(device_per_call_path.find(pair_call_path) !=
           device_per_call_path.end());

    const auto &source_device = device_per_call_path[source_call_path];
    const auto &pair_device = device_per_call_path[pair_call_path];

    call_path_constraint.process(R3S::R3S_cfg_get_z3_context(cfg),
                                 source_device, pair_device);

    auto source_packet_fields =
        call_path_constraint.get_packet_fields(source_device);

    if (packet_fields_per_device.find(source_device) ==
        packet_fields_per_device.end()) {
      packet_fields_per_device[source_device] = source_packet_fields;
    } else {
      packet_fields_per_device[source_device] = interset_packet_fields(
          packet_fields_per_device[source_device], source_packet_fields);
    }

    auto pair_packet_fields =
        call_path_constraint.get_packet_fields(pair_device);

    if (packet_fields_per_device.find(pair_device) ==
        packet_fields_per_device.end()) {
      packet_fields_per_device[pair_device] = pair_packet_fields;
    } else {
      packet_fields_per_device[pair_device] = interset_packet_fields(
          packet_fields_per_device[pair_device], pair_packet_fields);
    }

    Constraint *constraint = new CallPathsConstraint(call_path_constraint);
    constraints.emplace_back(constraint);
  }

  for (auto libvig_access_constraint : libvig_access_constraints) {
    libvig_access_constraint.process();

    auto devices = std::array<unsigned int, 2>{
        libvig_access_constraint.get_devices().first,
        libvig_access_constraint.get_devices().second};

    for (auto device : devices) {

      if (!analyse_constraint(&libvig_access_constraint)) {
        continue;
      }

      auto device_packet_fields =
          libvig_access_constraint.get_packet_fields(device);

      std::sort(device_packet_fields.begin(), device_packet_fields.end());

      if (packet_fields_per_device.find(device) ==
          packet_fields_per_device.end()) {
        packet_fields_per_device[device] = device_packet_fields;
        continue;
      }

      auto stored_packet_fields = packet_fields_per_device[device];
      auto intersection =
          interset_packet_fields(stored_packet_fields, device_packet_fields);

      if (intersection.size() > 0 &&
          intersection != packet_fields_per_device[device]) {
        packet_fields_per_device[device] = intersection;
      } else if (intersection.size() == 0) {

        Logger::error() << "\n";

        Logger::error() << "========================================"
                        << "\n";
        Logger::error() << "\n";
        Logger::error() << "        Incompatible constraints        "
                        << "\n";
        Logger::error() << "\n";
        Logger::error() << "========================================"
                        << "\n";

        Logger::error() << "\n";

        Logger::error() << "Commited packet fields: "
                        << "\n";
        for (const auto &device_pfs_pair : packet_fields_per_device) {
          Logger::error() << "  "
                          << "Device " << device_pfs_pair.first << ":"
                          << "\n";
          for (const auto &pf : device_pfs_pair.second) {
            Logger::error() << "    " << R3S::R3S_pf_to_string(pf) << "\n";
          }
        }
        Logger::error() << "\n";

        Logger::error() << "Incoming constraint (device " << device << "):"
                        << "\n";
        Logger::error() << libvig_access_constraint << "\n";

        Logger::error() << "\n";
        Logger::error() << "Associated libvig accesses:"
                        << "\n";

        Logger::error() << "\n";
        Logger::error() << libvig_access_constraint.get_first_access() << "\n";

        Logger::error() << "\n";
        Logger::error() << libvig_access_constraint.get_second_access() << "\n";

        exit(0);
      }

      Constraint *constraint =
          new LibvigAccessConstraint(libvig_access_constraint);

      constraints.emplace_back(constraint);
    }
  }
}

void RSSConfigBuilder::optimize_constraints() {}

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

  R3S::R3S_cfg_set_user_data(cfg, (void *)&constraints);

  if (constraints.size() == 0) {
    Logger::debug() << "No constraints. Generating random keys.";
    Logger::debug() << "\n";

    for (unsigned i = 0; i < cfg->n_keys; i++) {
      R3S::R3S_key_rand(cfg, keys[i]);
    }

    rss_config.set_keys(keys, cfg->n_keys);
    delete[] keys;

    return;
  }

  Logger::debug() << "Running the solver now. This might take a while...";
  Logger::debug() << "\n";

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

    device_per_call_path[access.get_metadata().get_file()] = src_device;

    auto src_it =
        std::find(unique_devices.begin(), unique_devices.end(), src_device);

    if (src_it == unique_devices.end()) {
      unique_devices.push_back(src_device);
    }

    if (!access.is_dst_device_set()) continue;

    auto dst_device = access.get_dst_device();
    auto dst_it =
        std::find(unique_devices.begin(), unique_devices.end(), dst_device);

    if (dst_it == unique_devices.end()) {
      unique_devices.push_back(dst_device);
    }
  }

  if (unique_devices.size() == 0) {
    Logger::warn() << "No devices. Using default unique devices value (2)."
                   << "\n";
    unique_devices.push_back(0);
    unique_devices.push_back(1);
  }
}

std::vector<LibvigAccess>
RSSConfigBuilder::filter_reads_without_writes_on_objects(
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
      if (access.get_object() != object) return false;

      return access.get_operation() == LibvigAccess::Operation::READ ||
             access.get_operation() == LibvigAccess::Operation::VERIFY;
    };

    auto found_read = std::find_if(accesses.begin(), accesses.end(),
                                   read_op_finder) != accesses.end();

    auto write_op_finder = [&](const LibvigAccess & access)->bool {
      if (access.get_object() != object) return false;

      return access.get_operation() == LibvigAccess::Operation::WRITE ||
             access.get_operation() == LibvigAccess::Operation::CREATE ||
             access.get_operation() == LibvigAccess::Operation::UPDATE;
    };

    auto found_write = std::find_if(accesses.begin(), accesses.end(),
                                    write_op_finder) != accesses.end();

    if (found_read && !found_write) {
      Logger::warn() << "Reads with no writes on object ";
      Logger::warn() << object;
      Logger::warn() << "\n";

      access_by_object.insert({object, false});
      continue;
    }

    access_by_object.insert({object, true});
    trimmed_accesses.push_back(access);
  }

  return trimmed_accesses;
}

bool RSSConfigBuilder::is_write_modifying(const std::vector<LibvigAccess> &cp,
                                          LibvigAccess write) {
  assert(write.get_operation() == LibvigAccess::Operation::WRITE ||
         write.get_operation() == LibvigAccess::Operation::UPDATE);

  if (write.get_operation() == LibvigAccess::Operation::UPDATE) {
    return true;
  }

  auto is_read_access_in_same_data_structure = [&](const LibvigAccess & access)
      ->bool {
    auto write_data_structure = write.get_metadata().get_data_structure();
    auto access_data_structure = access.get_metadata().get_data_structure();

    if (write_data_structure != access_data_structure) return false;

    return access.get_operation() == LibvigAccess::Operation::READ;
  };

  auto read_it =
      std::find_if(cp.begin(), cp.end(), is_read_access_in_same_data_structure);

  if (read_it == cp.end()) return true;

  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);

  auto read_arg = read_it->get_argument(LibvigAccessArgument::Type::RESULT);
  auto write_arg = write.get_argument(LibvigAccessArgument::Type::WRITE);

  auto result_expr = Constraint::parse_expr(ctx, read_arg.get_expression());
  auto write_expr = Constraint::parse_expr(ctx, write_arg.get_expression());

  return !R3S::Z3_is_eq_ast(ctx, write_expr, result_expr);
}

bool RSSConfigBuilder::are_call_paths_equivalent(
    const std::vector<LibvigAccess> &cp1,
    const std::vector<LibvigAccess> &cp2) {
  assert(cp1.size() && cp2.size());

  // Compare destination devices,
  // i.e., is the packet always dropped
  // or always sent to the same device?

  auto &access = cp1[0];
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

  auto is_not_write_access = [](const LibvigAccess & access)->bool {
    return access.get_operation() != LibvigAccess::Operation::WRITE &&
           access.get_operation() != LibvigAccess::Operation::UPDATE;
  };

  write_accesses_1.erase(
      std::remove_if(write_accesses_1.begin(), write_accesses_1.end(),
                     is_not_write_access),
      write_accesses_1.end());
  write_accesses_2.erase(
      std::remove_if(write_accesses_2.begin(), write_accesses_2.end(),
                     is_not_write_access),
      write_accesses_2.end());

  for (const auto &access : write_accesses_1) {
    if (is_write_modifying(cp1, access)) {
      Logger::error()
          << "Incompatible call paths: unable to bypass dchain interpretation."
          << "\n";
      Logger::error() << "Access leading to incompatibility of call paths:"
                      << "\n";
      Logger::error() << access << "\n";
      Logger::error() << "\n";
      return false;
    }
  }

  for (const auto &access : write_accesses_2) {
    if (is_write_modifying(cp2, access)) {
      Logger::error()
          << "Incompatible call paths: unable to bypass dchain interpretation."
          << "\n";
      Logger::error() << "Access leading to incompatibility of call paths:"
                      << "\n";
      Logger::error() << access << "\n";
      Logger::error() << "\n";
      return false;
    }
  }

  return true;
}

void RSSConfigBuilder::remove_constraints_from_object(unsigned int obj) {
  auto constraint_from_object = [&](const LibvigAccessConstraint & constraint)
      ->bool {
    const LibvigAccess &a1 = constraint.get_first_access();
    const LibvigAccess &a2 = constraint.get_second_access();

    assert(a1.get_object() == a2.get_object());
    return a1.get_object() == obj;
  };

  libvig_access_constraints.erase(
      std::remove_if(libvig_access_constraints.begin(),
                     libvig_access_constraints.end(), constraint_from_object),
      libvig_access_constraints.end());
}

void RSSConfigBuilder::remove_constraints_with_access(unsigned int access_id) {
  auto constraint_with_access = [&](const LibvigAccessConstraint & constraint)
      ->bool {
    if (constraint.get_first_access().get_id() != access_id &&
        constraint.get_second_access().get_id() != access_id) {
      return false;
    }

    return true;
  };

  libvig_access_constraints.erase(
      std::remove_if(libvig_access_constraints.begin(),
                     libvig_access_constraints.end(), constraint_with_access),
      libvig_access_constraints.end());
}

void RSSConfigBuilder::remove_constraints_with_pfs(
    unsigned int device, std::vector<R3S::R3S_pf_t> pfs,
    std::string call_path) {
  auto constraint_with_pfs = [&](LibvigAccessConstraint constraint)->bool {
    auto first_call_path =
        constraint.get_first_access().get_metadata().get_file();
    auto second_call_path =
        constraint.get_second_access().get_metadata().get_file();

    if (first_call_path != call_path && second_call_path != call_path) {
      return false;
    }

    constraint.process();
    auto constraint_pfs = constraint.get_packet_fields(device);

    if (constraint_pfs.size() != pfs.size()) {
      return false;
    }

    std::sort(constraint_pfs.begin(), constraint_pfs.end());
    std::sort(pfs.begin(), pfs.end());

    return std::equal(constraint_pfs.begin(), constraint_pfs.end(),
                      pfs.begin());
  };

  libvig_access_constraints.erase(
      std::remove_if(libvig_access_constraints.begin(),
                     libvig_access_constraints.end(), constraint_with_pfs),
      libvig_access_constraints.end());
}

void RSSConfigBuilder::remove_equivalent_index_dchain_constraints(
    unsigned int device,
    const std::vector<R3S::R3S_pf_t> comparing_packet_fields) {
  auto dchain_equivalent_constraint = [&](LibvigAccessConstraint constraint)
      ->bool {
    constraint.process();

    if (!constraint.has_non_packet_field_dependency("new_index")) {
      return false;
    }

    for (const auto &packet_field : comparing_packet_fields) {
      if (!constraint.has_packet_field(packet_field, device)) {
        return false;
      }
    }

    return true;
  };

  libvig_access_constraints.erase(
      std::remove_if(libvig_access_constraints.begin(),
                     libvig_access_constraints.end(),
                     dchain_equivalent_constraint),
      libvig_access_constraints.end());
}

void RSSConfigBuilder::verify_dchain_correctness(
    const std::vector<LibvigAccess> &accesses,
    const LibvigAccess &dchain_verify) {
  assert(dchain_verify.get_operation() == LibvigAccess::Operation::VERIFY);

  auto read_arg = dchain_verify.get_argument(LibvigAccessArgument::Type::READ);
  auto dependencies = read_arg.get_dependencies();
  auto packet_fields = dependencies.get_unique_packet_fields();

  if (packet_fields.size() == 0) {
    return;
  }

  std::map<std::string, std::vector<LibvigAccess> > call_paths;
  for (const auto &access : accesses) {
    auto call_path = access.get_metadata().get_file();
    call_paths[call_path].push_back(access);
  }

  std::map<std::string, std::vector<LibvigAccess> >
      failed_verifications_call_paths;
  std::map<std::string, std::vector<LibvigAccess> >
      successful_verifications_call_paths;
  std::map<std::string, std::vector<LibvigAccess> >
      successful_verifications_failed_constraints_call_paths;

  auto is_failed_verification = [](const LibvigAccess & access)->bool {
    return access.get_metadata().get_interface() ==
               "dchain_is_index_allocated" &&
           access.is_success_set() && access.get_success() == 0;
  };

  auto is_successful_verification = [](const LibvigAccess & access)->bool {
    return access.get_metadata().get_interface() ==
               "dchain_is_index_allocated" &&
           access.is_success_set() && access.get_success() != 0;
  };

  auto has_constraints_with_other_call_path = [&](const LibvigAccess & access)
      ->bool {
    const auto &metadata = access.get_metadata();
    const auto &call_path_fname = metadata.get_file();

    auto found_it = std::find_if(
        call_paths_constraints.begin(), call_paths_constraints.end(),
        [&](const CallPathsConstraint & call_path_constraint)->bool {
          return call_path_fname ==
                 call_path_constraint.get_call_path_info(
                                          CallPathInfo::Type::SOURCE)
                     .get_call_path();
        });

    return found_it != call_paths_constraints.end();
  };

  for (auto call_path : call_paths) {
    auto has_failed_verification_it =
        std::find_if(call_path.second.begin(), call_path.second.end(),
                     is_failed_verification);

    auto has_failed_verification =
        has_failed_verification_it != call_path.second.end();

    if (has_failed_verification) {
      failed_verifications_call_paths[call_path.first] = call_path.second;
      continue;
    }

    auto has_successful_verification_it =
        std::find_if(call_path.second.begin(), call_path.second.end(),
                     is_successful_verification);

    auto has_successful_verification =
        has_successful_verification_it != call_path.second.end();

    auto has_constraints_it =
        std::find_if(call_path.second.begin(), call_path.second.end(),
                     has_constraints_with_other_call_path);

    auto has_constraints = has_constraints_it != call_path.second.end();

    if (has_successful_verification && has_constraints) {
      successful_verifications_call_paths[call_path.first] = call_path.second;
    } else if (has_successful_verification) {
      successful_verifications_failed_constraints_call_paths[call_path.first] =
          call_path.second;
    }
  }

  auto equivalent_failures = true;
  for (const auto &failed_verification_pair : failed_verifications_call_paths) {
    for (const auto &successful_verifications_failed_constraints_pair :
         successful_verifications_failed_constraints_call_paths) {

      // TODO: maybe compare equivalence only after dchain verification?
      equivalent_failures =
          equivalent_failures &&
          are_call_paths_equivalent(
              failed_verification_pair.second,
              successful_verifications_failed_constraints_pair.second);

      if (!equivalent_failures) break;
    }

    if (!equivalent_failures) break;
  }

  if (equivalent_failures) {
    remove_constraints_from_object(dchain_verify.get_object());
    remove_equivalent_index_dchain_constraints(dchain_verify.get_src_device(),
                                               packet_fields);

    for (const auto &cp : successful_verifications_call_paths) {
      remove_constraints_with_pfs(dchain_verify.get_src_device(), packet_fields,
                                  cp.first);
    }

    for (const auto &cp :
         successful_verifications_failed_constraints_call_paths) {
      remove_constraints_with_pfs(dchain_verify.get_src_device(), packet_fields,
                                  cp.first);
    }

    return;
  }

  Logger::error()
      << "Indexes generated by a dchain are being interpreted as packet fields."
      << "\n";
  Logger::error() << "The generation of these indexes doesn't take into "
                     "consideration the RSS hash process."
                  << "\n";
  Logger::error()
      << "Because of this, it is impossible to correctly send packets to the "
         "same cores where these indexes were generated."
      << "\n";
  Logger::error() << "\n";
  Logger::error() << "Parallel incompatible access:"
                  << "\n";
  Logger::error() << dchain_verify << "\n";

  exit(1);
}

void RSSConfigBuilder::analyse_dchain_interpretations(
    const std::vector<LibvigAccess> &accesses) {
  for (const auto &access : accesses) {

    // Special case: this function loops over a dchain looking for an available
    // index. This is not parallel correct.
    if (access.get_metadata().get_interface() ==
        "cht_find_preferred_available_backend") {
      Logger::error() << "dchain correctness violated: ";
      Logger::error() << "use of 'cht_find_preferred_available_backend' "
                         "prohibits the existence"
                      << " of a lock-free parallel implementation."
                      << "\n";
      Logger::error() << "\n";

      Logger::error() << "Parallel incompatible access:"
                      << "\n";
      Logger::error() << access << "\n";

      exit(1);
    }

    if (access.get_operation() != LibvigAccess::Operation::VERIFY) continue;

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
R3S::Z3_ast RSSConfigBuilder::ast_equal_association(R3S::Z3_context ctx,
                                                    R3S::Z3_ast root,
                                                    R3S::Z3_ast target) {
  R3S::Z3_ast associated;

  if (Z3_get_ast_kind(ctx, root) != R3S::Z3_APP_AST) return nullptr;

  R3S::Z3_app app = Z3_to_app(ctx, root);
  unsigned num_fields = Z3_get_app_num_args(ctx, app);

  for (unsigned i = 0; i < num_fields; i++) {
    if (Z3_is_eq_ast(ctx, Z3_get_app_arg(ctx, app, i), target)) {
      assert(num_fields == 2);
      associated = Z3_get_app_arg(ctx, app, num_fields - i - 1);
      return associated;
    }

    associated =
        ast_equal_association(ctx, Z3_get_app_arg(ctx, app, i), target);

    if (associated) {
      return associated;
    }
  }

  return nullptr;
}

R3S::Z3_ast RSSConfigBuilder::ast_replace(R3S::Z3_context ctx, R3S::Z3_ast root,
                                          R3S::Z3_ast target, R3S::Z3_ast dst) {
  if (Z3_get_ast_kind(ctx, root) != R3S::Z3_APP_AST) return root;

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

std::vector<std::shared_ptr<Constraint> >
RSSConfigBuilder::get_constraints_between_devices(
    std::vector<std::shared_ptr<Constraint> > constraints,
    unsigned int p1_device, unsigned int p2_device) {
  auto filter = [&](const std::shared_ptr<Constraint> & constraint)->bool {
    const auto &devices = constraint->get_devices();
    auto first_device = devices.first;
    auto second_device = devices.second;

    return p1_device != first_device || p2_device != second_device;
  };

  constraints.erase(
      std::remove_if(constraints.begin(), constraints.end(), filter),
      constraints.end());

  return constraints;
}

R3S::Z3_ast RSSConfigBuilder::constraint_to_solver_input(
    R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2,
    std::shared_ptr<Constraint> constraint) {
  R3S::Z3_context ctx = R3S::R3S_cfg_get_z3_context(cfg);
  R3S::Z3_ast constraint_expression = constraint->get_expression();

  for (const auto &packet_dependency_expression :
       constraint->get_packet_dependencies_expressions()) {
    auto expression = packet_dependency_expression.get_expression();
    R3S::Z3_ast target_ast;

    R3S::R3S_packet_ast_t target_packet;

    if (packet_dependency_expression.get_packet_chunks_id() ==
        constraint->get_packet_chunks_ids().first) {
      target_packet = p1;
    } else if (packet_dependency_expression.get_packet_chunks_id() ==
               constraint->get_packet_chunks_ids().second) {
      target_packet = p2;
    } else {
      assert(false &&
             "Invalid target packet: chunk id in packet dependency "
             "expression wrongly associated with constraint");
    }

    auto compatible_dependency =
        packet_dependency_expression.get_dependency_compatible_with_packet(
            cfg, target_packet);

    if (compatible_dependency) {
      R3S::R3S_status_t status;

      auto processed_dependency = dynamic_cast<PacketDependencyProcessed *>(
          compatible_dependency.get());
      auto packet_field = processed_dependency->get_packet_field();

      R3S::Z3_ast packet_field_ast;
      status = R3S::R3S_packet_extract_pf(cfg, target_packet, packet_field,
                                          &packet_field_ast);
      assert(status == R3S::R3S_STATUS_SUCCESS);

      auto packet_field_sort = Z3_get_sort(ctx, packet_field_ast);
      auto packet_field_size = Z3_get_bv_sort_size(ctx, packet_field_sort);

      unsigned high, low;

      if (packet_field == R3S::R3S_PF_IPV4_SRC ||
          packet_field == R3S::R3S_PF_IPV4_DST) {
        high = (processed_dependency->get_bytes() + 1) * 8 - 1;
        low = high - 7;
      } else {
        high = packet_field_size - processed_dependency->get_bytes() * 8 - 1;
        low = high - 7;
      }

      target_ast = Z3_mk_extract(ctx, high, low, packet_field_ast);
    } else if (packet_dependency_expression.get_associated_dependencies()[0]
                   ->should_ignore()) {
      auto associated_dependencies =
          packet_dependency_expression.get_associated_dependencies();
      assert(associated_dependencies.size() == 1);
      target_ast = Z3_mk_bvxor(ctx, expression, expression);
    } else {
      return nullptr;
    }

    constraint_expression =
        ast_replace(ctx, constraint_expression, expression, target_ast);
  }

  return Z3_simplify(ctx, constraint_expression);
}

R3S::Z3_ast RSSConfigBuilder::make_solver_constraints(
    R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t p1, R3S::R3S_packet_ast_t p2) {
  auto constraints =
      *((std::vector<std::shared_ptr<Constraint> > *)R3S::R3S_cfg_get_user_data(
           cfg));
  auto ctx = R3S::R3S_cfg_get_z3_context(cfg);

  std::vector<R3S::Z3_ast> generated_constraints;
  R3S::Z3_ast final_constraint;

  auto filtered_constraints =
      get_constraints_between_devices(constraints, p1.key_id, p2.key_id);

  for (auto &constraint : filtered_constraints) {
    auto constraint_expression =
        constraint_to_solver_input(cfg, p1, p2, constraint);

    if (!constraint_expression) continue;

    generated_constraints.push_back(constraint_expression);
  }

  if (generated_constraints.size() == 0) return NULL;

  if (generated_constraints.size() > 1) {
    final_constraint =
        R3S::Z3_simplify(ctx, R3S::Z3_mk_and(ctx, generated_constraints.size(),
                                             &generated_constraints[0]));
  } else {
    final_constraint = generated_constraints[0];
  }

  std::stringstream ss;
  ss << "Constraints:\n";
  ss << R3S::Z3_ast_to_string(ctx, final_constraint);
  ss << "\n";

  Logger::warn() << ss.str();

  return final_constraint;
}

}  // namespace ParallelSynthesizer
