#pragma once

#include "constraint.h"
#include "rss_config.h"
#include "lib_access.h"

#include <vector>
#include <map>

namespace RS3 {
#include <rs3.h>
}

namespace ParallelSynthesizer {

class RSSConfigBuilder {

private:
  RS3::RS3_cfg_t cfg;
  std::vector<std::shared_ptr<Constraint> > constraints;

  std::vector<LibvigAccessConstraint> lib_access_constraints;
  std::vector<CallPathsConstraint> call_paths_constraints;

  std::map<std::string, unsigned int> device_per_call_path;
  std::vector<unsigned int> unique_devices;
  std::vector<std::pair<LibvigAccess, LibvigAccess> > unique_access_pairs;
  std::vector<RS3::RS3_pf_t> unique_packet_fields_dependencies;
  std::vector<RS3::RS3_cnstrs_func> solver_constraints_generators;

  RSSConfig rss_config;

private:
  void load_rss_config_options();
  void load_solver_constraints_generators();
  int get_device_index(unsigned int device) const;

  void merge_unique_packet_field_dependencies(
      const std::vector<RS3::RS3_pf_t> &packet_fields);

  bool is_access_pair_already_stored(
      const std::pair<LibvigAccess, LibvigAccess> &pair);

  void fill_unique_devices(const std::vector<LibvigAccess> &accesses);
  std::vector<LibvigAccess> filter_reads_without_writes_on_objects(
      const std::vector<LibvigAccess> &accesses);

  void optimize_constraints();
  void remove_constraints_from_object(unsigned int obj);
  void remove_constraints_with_access(unsigned int access_id);
  void remove_constraints_with_pfs(unsigned int device,
                                   std::vector<RS3::RS3_pf_t> pfs,
                                   std::string call_path);
  void remove_equivalent_index_dchain_constraints(
      unsigned int device, const std::vector<RS3::RS3_pf_t> packet_fields);
  void
  analyse_dchain_interpretations(const std::vector<LibvigAccess> &accesses);
  bool is_write_modifying(const std::vector<LibvigAccess> &cp,
                          LibvigAccess write);
  bool are_call_paths_equivalent(const std::vector<LibvigAccess> &cp1,
                                 const std::vector<LibvigAccess> &cp2);
  void verify_dchain_correctness(const std::vector<LibvigAccess> &accesses,
                                 const LibvigAccess &dchain_verify);

  void filter_constraints();
  void fill_lib_access_constraints(const std::vector<LibvigAccess> &accesses);
  void generate_solver_constraints();

  static std::vector<std::shared_ptr<Constraint> >
  get_constraints_between_devices(
      std::vector<std::shared_ptr<Constraint> > constraints,
      unsigned int p1_device, unsigned int p2_device);

  static RS3::Z3_ast
  constraint_to_solver_input(RS3::RS3_cfg_t cfg, RS3::RS3_packet_ast_t p1,
                             RS3::RS3_packet_ast_t p2,
                             std::shared_ptr<Constraint> constraint);

  static RS3::Z3_ast make_solver_constraints(RS3::RS3_cfg_t cfg,
                                             RS3::RS3_packet_ast_t p1,
                                             RS3::RS3_packet_ast_t p2);

public:
  RSSConfigBuilder(
      const std::vector<LibvigAccess> &accesses,
      const std::vector<CallPathsConstraint> &_call_paths_constraints)
      : call_paths_constraints(_call_paths_constraints) {

    RS3::RS3_cfg_init(&cfg);
    RS3::RS3_cfg_set_skew_analysis(cfg, true);

    fill_unique_devices(accesses);

    auto trimmed_accesses = filter_reads_without_writes_on_objects(accesses);

    fill_lib_access_constraints(trimmed_accesses);
    analyse_dchain_interpretations(trimmed_accesses);

    Logger::debug() << "\n";
    Logger::debug() << "Packet field dependencies:";
    Logger::debug() << "\n";
    for (auto &pf : unique_packet_fields_dependencies) {
      Logger::debug() << "  " << RS3::RS3_pf_to_string(pf);
      Logger::debug() << "\n";
    }

    Logger::debug() << "\n";
    Logger::debug() << "Devices:";
    Logger::debug() << "\n";
    for (const auto &device : unique_devices) {
      Logger::debug() << "  " << device;
      Logger::debug() << "\n";
    }

    load_rss_config_options();
    generate_solver_constraints();
    filter_constraints();
    optimize_constraints();

    Logger::debug() << "\nRS3 configuration:\n"
                    << RS3::RS3_cfg_to_string(cfg) << "\n";
  }

  const RS3::RS3_cfg_t &get_cfg() const { return cfg; }
  const std::vector<LibvigAccessConstraint> &
  get_lib_access_constraints() const {
    return lib_access_constraints;
  }
  RSSConfig &get_generated_rss_cfg() { return rss_config; }

  static RS3::Z3_ast ast_replace(RS3::Z3_context ctx, RS3::Z3_ast root,
                                 RS3::Z3_ast target, RS3::Z3_ast dst);

  static RS3::Z3_ast ast_equal_association(RS3::Z3_context ctx,
                                           RS3::Z3_ast root,
                                           RS3::Z3_ast target);

  void build_rss_config();

  std::pair<RS3::RS3_packet_t, RS3::RS3_packet_t>
  generate_packets(unsigned device1, unsigned device2);

  ~RSSConfigBuilder() { RS3::RS3_cfg_delete(cfg); }
};
} // namespace ParallelSynthesizer
