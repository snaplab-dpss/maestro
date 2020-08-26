#pragma once

#include "libvig_access.h"

#include <iostream>
#include <vector>
#include <string>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class PacketDependenciesExpression {

private:
  R3S::Z3_context ctx;
  R3S::Z3_ast expression;
  unsigned int index;
  unsigned int packet_chunks_id;

  std::vector< std::shared_ptr<PacketDependency> > dependencies;

public:
  PacketDependenciesExpression(const R3S::Z3_context &_ctx,
                        const R3S::Z3_ast &_expression,
                        const unsigned int &_index,
                        const unsigned int &_packet_chunks_id)
      : ctx(_ctx), expression(_expression), index(_index),
        packet_chunks_id(_packet_chunks_id) {}

  PacketDependenciesExpression(const PacketDependenciesExpression &pde)
      : ctx(pde.ctx), expression(pde.expression),
        index(pde.index), packet_chunks_id(pde.packet_chunks_id) {
    for (auto dep : pde.dependencies)
      store_dependency(dep.get());
  }

  const R3S::Z3_context &get_context() const { return ctx; }
  const R3S::Z3_ast &get_expression() const { return expression; }
  const unsigned int &get_index() const { return index; }
  const unsigned int &get_packet_chunks_id() const { return packet_chunks_id; }

  const std::vector< std::shared_ptr<PacketDependency> >& get_associated_dependencies() const {
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

      const auto processed = dynamic_cast<PacketDependencyProcessed*>(dependency.get());
      const auto packet_field = processed->get_packet_field();

      auto found_it = std::find(packet_fields.begin(), packet_fields.end(), packet_field);

      if (found_it == packet_fields.end()) {
        packet_fields.push_back(packet_field);
      }
    }

    return packet_fields;
  }

  const std::shared_ptr<PacketDependency> get_dependency_compatible_with_packet(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t packet) const {
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

      const auto processed = dynamic_cast<PacketDependencyProcessed*>(dependency.get());
      const auto packet_field = processed->get_packet_field();

      R3S::R3S_status_t status = R3S_packet_extract_pf(cfg, packet, packet_field, &pf_ast);

      assert(status != R3S::R3S_STATUS_SUCCESS || !compatible_dependency);

      if (status == R3S::R3S_STATUS_SUCCESS) {
        compatible_dependency = dependency;
        break;
      }
    }

    return compatible_dependency;
  }

  void store_dependency(const PacketDependency* dependency) {
    assert(dependency);
    dependencies.push_back(std::move(dependency->clone_packet_dependency()));
  }

  friend bool operator<(const PacketDependenciesExpression &lhs,
                        const PacketDependenciesExpression &rhs);

  friend bool operator==(const PacketDependenciesExpression &lhs,
                         const PacketDependenciesExpression& rhs);

  friend std::ostream &operator<<(std::ostream &os,
                                  const PacketDependenciesExpression &arg);

  static const std::string PACKET_CHUNKS_NAME_PATTERN;
};

class Constraint {

private:
  R3S::Z3_context ctx;
  LibvigAccess first;
  LibvigAccess second;

  R3S::Z3_ast expression;
  std::pair<int, int> packet_chunks_ids;
  std::vector<PacketDependenciesExpression> packet_dependencies_expressions;

private:
  void store_unique_packet_dependencies_expression(const PacketDependenciesExpression& pde);

  void check_incompatible_dependencies();
  void generate_expression_from_read_args();
  void fill_packet_fields(R3S::Z3_ast &expression);
  void zip_packet_fields_expression_and_values();

public:
  Constraint(const LibvigAccess &_first, const LibvigAccess &_second,
             const R3S::Z3_context &_ctx)
      : ctx(_ctx), first(_first), second(_second) {
    check_incompatible_dependencies();
    generate_expression_from_read_args();

    packet_chunks_ids = std::make_pair(-1, -1);

    fill_packet_fields(expression);
    zip_packet_fields_expression_and_values();
  }

  Constraint(const Constraint &constraint)
      : ctx(constraint.ctx),
        first(constraint.first),
        second(constraint.second),
        expression(constraint.expression),
        packet_chunks_ids(constraint.packet_chunks_ids) {
    packet_dependencies_expressions = constraint.packet_dependencies_expressions;
  }

  const R3S::Z3_context &get_context() const { return ctx; }
  const LibvigAccess &get_first_access() const { return first; }
  const LibvigAccess &get_second_access() const { return second; }
  const R3S::Z3_ast get_expression() const { return expression; }

  const std::pair<int, int> &get_packet_chunks_ids() const {
    return packet_chunks_ids;
  }

  const std::vector<PacketDependenciesExpression>& get_packet_dependencies_expressions() const {
    return packet_dependencies_expressions;
  }

  bool has_packet_field(R3S::R3S_pf_t packet_field) const {
    return has_packet_field(packet_field, first.get_src_device()) ||
           has_packet_field(packet_field, second.get_src_device());
  }

  bool has_packet_field(R3S::R3S_pf_t packet_field, unsigned int device) const {
    return get_packet_dependency_expression(device, packet_field) != nullptr;
  }

  const PacketDependenciesExpression* get_packet_dependencies_expression(R3S::Z3_ast expression) const {
    if (expression == nullptr) {
      return nullptr;
    }

    for (const auto& packet_dependencies_expression : packet_dependencies_expressions) {
      auto context = packet_dependencies_expression.get_context();
      auto current_expr = packet_dependencies_expression.get_expression();

      if (R3S::Z3_is_eq_ast(context, expression, current_expr)) {
        return &packet_dependencies_expression;
      }
    }

    return nullptr;
  }

  const PacketDependenciesExpression* get_packet_dependency_expression(unsigned int device, R3S::R3S_pf_t packet_field) const {
    int target_packet_chunk_id;

    if (device == first.get_src_device()) {
      target_packet_chunk_id = packet_chunks_ids.first;
    }

    else if (device == second.get_src_device()) {
      target_packet_chunk_id = packet_chunks_ids.second;
    }

    else {
      return nullptr;
    }

    for (const auto& packet_dependencies_expression : packet_dependencies_expressions) {
      if (target_packet_chunk_id < 0) {
        continue;
      }

      if (packet_dependencies_expression.get_packet_chunks_id() != target_packet_chunk_id) {
        continue;
      }

      auto associated_dependencies = packet_dependencies_expression.get_associated_dependencies();

      for (const auto& dependency : associated_dependencies) {
        if (!dependency->is_processed())
          continue;

        if (!dependency->is_rss_compatible())
          continue;

        if (dependency->should_ignore())
          continue;

        const auto processed = dynamic_cast<PacketDependencyProcessed *>(dependency.get());
        auto pf = processed->get_packet_field();

        if (pf == packet_field) {
          return &packet_dependencies_expression;
        }
      }
    }

    return nullptr;
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const Constraint &arg);

  static R3S::Z3_ast parse_expr(R3S::Z3_context ctx, const std::string& expr_str);
};

class CallPathInfo {
public:
  enum Type {
    SOURCE, PAIR
  };

  static Type parse_call_path_info_type_token(const std::string& call_path_info_type) {
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
  std::pair<bool, std::string> symbol;

  DependencyManager dependencies;

public:
  CallPathInfo(const std::string& _call_path, const Type& _type, const std::pair<bool, std::string>& _symbol)
    : call_path(_call_path), type(_type), symbol(_symbol) {}

  CallPathInfo(const std::string& _call_path, const Type& _type, const std::string& _symbol)
    : call_path(_call_path), type(_type) {
    symbol = std::make_pair(true, _symbol);
  }

  CallPathInfo(const CallPathInfo& other)
    : call_path(other.call_path), type(other.type), symbol(other.symbol) {
    dependencies = other.dependencies;
  }

  const std::string& get_call_path() const { return call_path; }
  const Type& get_type() const { return type; }
  const std::string& get_symbol() const {
    assert(symbol.first);
    return symbol.second;
  }

  bool has_symbol() const { return symbol.first; }

  const DependencyManager& get_dependencies() const {
    return dependencies;
  }

  void sort_dependencies() {
    dependencies.sort();
  }

  void add_dependency(const Dependency *dependency) {
    dependencies.add_dependency(dependency);
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const CallPathInfo &arg);
};

class CallPathsConstraint {
private:
  std::string expression_str;

  CallPathInfo first;
  CallPathInfo second;

public:
  CallPathsConstraint(const std::string& _expression_str, const CallPathInfo& _first, const CallPathInfo& _second)
    : expression_str(_expression_str), first(_first), second(_second) {}

  CallPathsConstraint(const CallPathsConstraint& other)
    : expression_str(other.expression_str), first(other.first), second(other.second) {}

  const std::string& get_expression_str() const { return expression_str; }

  const CallPathInfo& get_call_path_info(CallPathInfo::Type type) const {
    if (first.get_type() == type)
      return first;

    if (second.get_type() == type)
      return second;

    assert(false && "Call path info type not found");
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const CallPathsConstraint &arg);
};

class CallPathsTranslation {
private:
  CallPathInfo first;
  CallPathInfo second;

public:
  CallPathsTranslation(const CallPathInfo& _first, const CallPathInfo& _second)
    : first(_first), second(_second) {}

  CallPathsTranslation(const CallPathsTranslation& other)
    : first(other.first), second(other.second) {}

  const CallPathInfo& get_call_path_info(CallPathInfo::Type type) const {
    if (first.get_type() == type)
      return first;

    if (second.get_type() == type)
      return second;

    assert(false && "Call path info type not found");
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const CallPathsTranslation &arg);
};

}
