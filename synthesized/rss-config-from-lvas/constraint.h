#pragma once

#include "libvig_access.h"

#include <iostream>
#include <vector>
#include <string>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class NonPacketDependencyExpression {
private:
  R3S::Z3_context ctx;
  R3S::Z3_ast expression;
  std::string symbol;

public:
  NonPacketDependencyExpression(const R3S::Z3_context &_ctx,
                                const R3S::Z3_ast &_expression,
                                const std::string &_symbol)
      : ctx(_ctx), expression(_expression), symbol(_symbol) {}

  NonPacketDependencyExpression(const NonPacketDependencyExpression &npde)
      : NonPacketDependencyExpression(npde.ctx, npde.expression, npde.symbol) {}

  const R3S::Z3_context &get_context() const { return ctx; }
  const R3S::Z3_ast &get_expression() const { return expression; }
  const std::string &get_symbol() const { return symbol; }

  friend bool operator==(const NonPacketDependencyExpression &lhs,
                         const NonPacketDependencyExpression &rhs);

  friend std::ostream &operator<<(std::ostream &os,
                                  const NonPacketDependencyExpression &arg);
};

class PacketDependenciesExpression {

private:
  R3S::Z3_context ctx;
  R3S::Z3_ast expression;
  unsigned int index;
  unsigned int packet_chunks_id;

  std::vector<std::shared_ptr<PacketDependency> > dependencies;

public:
  PacketDependenciesExpression(const R3S::Z3_context &_ctx,
                               const R3S::Z3_ast &_expression,
                               const unsigned int &_index,
                               const unsigned int &_packet_chunks_id)
      : ctx(_ctx), expression(_expression), index(_index),
        packet_chunks_id(_packet_chunks_id) {}

  PacketDependenciesExpression(const PacketDependenciesExpression &pde)
      : ctx(pde.ctx), expression(pde.expression), index(pde.index),
        packet_chunks_id(pde.packet_chunks_id) {
    for (auto dep : pde.dependencies)
      store_dependency(dep.get());
  }

  const R3S::Z3_context &get_context() const { return ctx; }
  const R3S::Z3_ast &get_expression() const { return expression; }
  const unsigned int &get_index() const { return index; }
  const unsigned int &get_packet_chunks_id() const { return packet_chunks_id; }

  const std::vector<std::shared_ptr<PacketDependency> > &
  get_associated_dependencies() const {
    return dependencies;
  }

  std::vector<R3S::R3S_pf_t> get_associated_dependencies_packet_fields() const {
    std::vector<R3S::R3S_pf_t> packet_fields;

    for (auto dependency : dependencies) {
      if (dependency->should_ignore()) {
        continue;
      }

      if (!dependency->is_rss_compatible()) {
        continue;
      }

      if (!dependency->is_processed()) {
        continue;
      }

      const auto processed =
          dynamic_cast<PacketDependencyProcessed *>(dependency.get());
      const auto packet_field = processed->get_packet_field();

      auto found_it =
          std::find(packet_fields.begin(), packet_fields.end(), packet_field);

      if (found_it == packet_fields.end()) {
        packet_fields.push_back(packet_field);
      }
    }

    return packet_fields;
  }

  const std::shared_ptr<PacketDependency>
  get_dependency_compatible_with_packet(R3S::R3S_cfg_t cfg,
                                        R3S::R3S_packet_ast_t packet) const {
    std::shared_ptr<PacketDependency> compatible_dependency;
    R3S::Z3_ast pf_ast;

    for (auto dependency : dependencies) {
      if (dependency->should_ignore()) {
        continue;
      }

      if (!dependency->is_rss_compatible()) {
        continue;
      }

      if (!dependency->is_processed()) {
        continue;
      }

      const auto processed =
          dynamic_cast<PacketDependencyProcessed *>(dependency.get());
      const auto packet_field = processed->get_packet_field();

      R3S::R3S_status_t status =
          R3S_packet_extract_pf(cfg, packet, packet_field, &pf_ast);

      assert(status != R3S::R3S_STATUS_SUCCESS || !compatible_dependency);

      if (status == R3S::R3S_STATUS_SUCCESS) {
        compatible_dependency = dependency;
        break;
      }
    }

    return compatible_dependency;
  }

  void store_dependency(const PacketDependency *dependency) {
    assert(dependency);
    dependencies.push_back(std::move(dependency->clone_packet_dependency()));
  }

  friend bool operator<(const PacketDependenciesExpression &lhs,
                        const PacketDependenciesExpression &rhs);

  friend bool operator==(const PacketDependenciesExpression &lhs,
                         const PacketDependenciesExpression &rhs);

  friend std::ostream &operator<<(std::ostream &os,
                                  const PacketDependenciesExpression &arg);

  static const std::string PACKET_CHUNKS_NAME_PATTERN;
};

class Constraint {
protected:
  enum Type {
    LibvigAccessType,
    CallPathType
  };

protected:
  Type type;

  R3S::Z3_context ctx;
  R3S::Z3_ast expression;

  std::pair<unsigned int, unsigned int> devices;
  std::pair<unsigned int, unsigned int> packet_chunks_ids;

  std::vector<PacketDependenciesExpression> packet_dependencies_expressions;
  std::vector<NonPacketDependencyExpression>
  non_packet_dependencies_expressions;

protected:
  void
  store_unique_dependencies_expression(const PacketDependenciesExpression &pde);
  void store_unique_dependencies_expression(
      const NonPacketDependencyExpression &npde);

  void fill_dependencies(R3S::Z3_ast &expression);
  void fill_non_packet_dependencies_expressions(R3S::Z3_ast &expression);
  void zip_packet_fields_expression_and_values(const DependencyManager &first,
                                               const DependencyManager &second);

  virtual void internal_process() = 0;

  // only a subclass can have access to these constructors
  Constraint(Type _type) : type(_type) {}
  Constraint(Type _type, R3S::Z3_context _ctx) : type(_type), ctx(_ctx) {}

public:
  Constraint(const Constraint &constraint)
      : type(constraint.type), ctx(constraint.ctx),
        expression(constraint.expression), devices(constraint.devices),
        packet_chunks_ids(constraint.packet_chunks_ids) {
    packet_dependencies_expressions =
        constraint.packet_dependencies_expressions;
    non_packet_dependencies_expressions =
        constraint.non_packet_dependencies_expressions;
  }

  Type get_type() const { return type; }
  const R3S::Z3_context &get_context() const { return ctx; }
  const R3S::Z3_ast get_expression() const { return expression; }

  const std::pair<unsigned int, unsigned int> &get_devices() const {
    return devices;
  }

  const std::pair<unsigned int, unsigned int> &get_packet_chunks_ids() const {
    return packet_chunks_ids;
  }

  const std::vector<PacketDependenciesExpression> &
  get_packet_dependencies_expressions() const {
    return packet_dependencies_expressions;
  }

  const std::vector<NonPacketDependencyExpression> &
  get_non_packet_dependencies_expressions() const {
    return non_packet_dependencies_expressions;
  }

  std::vector<R3S::R3S_pf_t> get_packet_fields(unsigned int device) const {
    assert(device == devices.first || device == devices.second);

    std::vector<R3S::R3S_pf_t> packet_fields;
    auto packet_chunk_id = devices.first == device ? packet_chunks_ids.first
                                                   : packet_chunks_ids.second;

    for (const auto &pde : packet_dependencies_expressions) {
      if (pde.get_packet_chunks_id() != packet_chunk_id)
        continue;

      auto pde_pfs = pde.get_associated_dependencies_packet_fields();

      for (const auto &pf : pde_pfs) {
        auto found_it =
            std::find(packet_fields.begin(), packet_fields.end(), pf);

        if (found_it == packet_fields.end()) {
          packet_fields.push_back(pf);
        }
      }
    }

    return packet_fields;
  }

  bool has_packet_field(R3S::R3S_pf_t packet_field) const {
    return has_packet_field(packet_field, devices.first) ||
           has_packet_field(packet_field, devices.second);
  }

  bool has_non_packet_field_dependency(const std::string &symbol_name) const {
    for (const auto &npde : non_packet_dependencies_expressions) {
      auto npde_symbol = npde.get_symbol();
      auto delim = npde_symbol.find(symbol_name);

      if (delim != std::string::npos) {
        return true;
      }
    }

    return false;
  }

  bool has_packet_field(R3S::R3S_pf_t packet_field, unsigned int device) const {
    return get_packet_dependency_expression(device, packet_field) != nullptr;
  }

  const PacketDependenciesExpression *
  get_packet_dependencies_expression(R3S::Z3_ast expression) const {
    if (expression == nullptr) {
      return nullptr;
    }

    for (const auto &packet_dependencies_expression :
         packet_dependencies_expressions) {
      auto context = packet_dependencies_expression.get_context();
      auto current_expr = packet_dependencies_expression.get_expression();

      if (R3S::Z3_is_eq_ast(context, expression, current_expr)) {
        return &packet_dependencies_expression;
      }
    }

    return nullptr;
  }

  const PacketDependenciesExpression *
  get_packet_dependency_expression(unsigned int device,
                                   R3S::R3S_pf_t packet_field) const {
    int target_packet_chunk_id;

    if (device == devices.first) {
      target_packet_chunk_id = packet_chunks_ids.first;
    } else if (device == devices.second) {
      target_packet_chunk_id = packet_chunks_ids.second;
    } else {
      return nullptr;
    }

    for (const auto &packet_dependencies_expression :
         packet_dependencies_expressions) {
      if (target_packet_chunk_id < 0) {
        continue;
      }

      if (packet_dependencies_expression.get_packet_chunks_id() !=
          target_packet_chunk_id) {
        continue;
      }

      auto associated_dependencies =
          packet_dependencies_expression.get_associated_dependencies();

      for (const auto &dependency : associated_dependencies) {
        if (!dependency->is_processed())
          continue;

        if (!dependency->is_rss_compatible())
          continue;

        if (dependency->should_ignore())
          continue;

        const auto processed =
            dynamic_cast<PacketDependencyProcessed *>(dependency.get());
        auto pf = processed->get_packet_field();

        if (pf == packet_field) {
          return &packet_dependencies_expression;
        }
      }
    }

    return nullptr;
  }

  static R3S::Z3_ast parse_expr(R3S::Z3_context ctx,
                                const std::string &expr_str);

  friend std::ostream &operator<<(std::ostream &os, const Constraint &arg);

  friend std::ostream &operator<<(std::ostream &os, Constraint *arg);
};

class LibvigAccessConstraint : public Constraint {

private:
  LibvigAccess first;
  LibvigAccess second;

private:
  void check_incompatible_dependencies();
  void generate_expression_from_read_args();

protected:
  void internal_process() override {
    const auto &first_device = first.get_src_device();
    const auto &second_device = second.get_src_device();

    assert(first.has_argument(LibvigAccessArgument::Type::READ));
    assert(second.has_argument(LibvigAccessArgument::Type::READ));

    auto first_read_arg = first.get_argument(LibvigAccessArgument::Type::READ);
    auto second_read_arg =
        second.get_argument(LibvigAccessArgument::Type::READ);

    auto first_read_arg_copy = first_read_arg;
    auto second_read_arg_copy = second_read_arg;

    first_read_arg_copy.sort_dependencies();
    second_read_arg_copy.sort_dependencies();

    const auto &first_deps = first_read_arg_copy.get_dependencies();
    const auto &second_deps = second_read_arg_copy.get_dependencies();

    devices = std::make_pair(first_device, second_device);

    packet_chunks_ids = std::make_pair(first.get_id(), second.get_id());

    fill_dependencies(expression);
    zip_packet_fields_expression_and_values(first_deps, second_deps);
  }

public:
  LibvigAccessConstraint(const LibvigAccess &_first,
                         const LibvigAccess &_second,
                         const R3S::Z3_context &_ctx)
      : Constraint(LibvigAccessType, _ctx),

        // This is an optimization for the solver (libR3S).
        // It comes up with a solution faster if the inter-devices constraints
        // have the bigger device first.
        first(_first.get_src_device() >= _second.get_src_device() ? _first
                                                                  : _second),
        second(_first.get_src_device() >= _second.get_src_device() ? _second
                                                                   : _first) {

    check_incompatible_dependencies();
    generate_expression_from_read_args();
  }

  LibvigAccessConstraint(const LibvigAccessConstraint &constraint)
      : Constraint(constraint), first(constraint.first),
        second(constraint.second) {}

  void process() { internal_process(); }

  const LibvigAccess &get_first_access() const { return first; }
  const LibvigAccess &get_second_access() const { return second; }

  friend std::ostream &operator<<(std::ostream &os,
                                  const LibvigAccessConstraint &arg);
};

class CallPathInfo {
public:
  enum Type {
    SOURCE,
    PAIR
  };

  static Type
  parse_call_path_info_type_token(const std::string &call_path_info_type) {
    if (call_path_info_type == Tokens::CallPathInfoType::SOURCE)
      return SOURCE;

    if (call_path_info_type == Tokens::CallPathInfoType::PAIR)
      return PAIR;

    Logger::error() << "Invalid argument type token \"";
    Logger::error() << call_path_info_type;
    Logger::error() << "\n";

    exit(1);
  }

private:
  std::string call_path;
  Type type;
  std::pair<bool, unsigned int> id;

  DependencyManager dependencies;

public:
  CallPathInfo(const std::string &_call_path, const Type &_type,
               const std::pair<bool, unsigned int> &_id)
      : call_path(_call_path), type(_type), id(_id) {}

  CallPathInfo(const std::string &_call_path, const Type &_type,
               unsigned int _id)
      : call_path(_call_path), type(_type) {
    id = std::make_pair(true, _id);
  }

  CallPathInfo(const CallPathInfo &other)
      : call_path(other.call_path), type(other.type), id(other.id) {
    dependencies = other.dependencies;
  }

  const std::string &get_call_path() const { return call_path; }
  const Type &get_type() const { return type; }
  unsigned int get_id() const {
    assert(id.first);
    return id.second;
  }

  bool has_id() const { return id.first; }

  const DependencyManager &get_dependencies() const { return dependencies; }

  void sort_dependencies() { dependencies.sort(); }

  void add_dependency(const Dependency *dependency) {
    dependencies.add_dependency(dependency);
  }

  friend std::ostream &operator<<(std::ostream &os, const CallPathInfo &arg);
};

class CallPathsConstraint : public Constraint {
private:
  std::string expression_str;

  CallPathInfo first;
  CallPathInfo second;

  unsigned int source_device;
  unsigned int pair_device;

protected:
  void internal_process() override {
    auto source = get_call_path_info(CallPathInfo::Type::SOURCE);
    auto pair = get_call_path_info(CallPathInfo::Type::PAIR);

    source.sort_dependencies();
    pair.sort_dependencies();

    const auto &source_deps = source.get_dependencies();
    const auto &pair_deps = pair.get_dependencies();

    const auto &source_id = source.get_id();
    const auto &pair_id = pair.get_id();

    expression = Constraint::parse_expr(ctx, expression_str);
    devices = std::make_pair(source_device, pair_device);

    packet_chunks_ids = std::make_pair(source_id, pair_id);

    fill_dependencies(expression);
    zip_packet_fields_expression_and_values(source_deps, pair_deps);
  }

public:
  CallPathsConstraint(const std::string &_expression_str,
                      const CallPathInfo &_first, const CallPathInfo &_second)
      : Constraint(CallPathType), expression_str(_expression_str),
        first(_first), second(_second) {}

  CallPathsConstraint(const CallPathsConstraint &other)
      : Constraint(other), expression_str(other.expression_str),
        first(other.first), second(other.second) {}

  void process(R3S::Z3_context _ctx, unsigned int _source_device,
               unsigned int _pair_device) {
    ctx = _ctx;
    source_device = _source_device;
    pair_device = _pair_device;
    internal_process();
  }

  const std::string &get_expression_str() const { return expression_str; }

  const CallPathInfo &get_call_path_info(CallPathInfo::Type type) const {
    if (first.get_type() == type)
      return first;

    if (second.get_type() == type)
      return second;

    assert(false && "Call path info type not found");
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const CallPathsConstraint &arg);
};

} // namespace ParallelSynthesizer
