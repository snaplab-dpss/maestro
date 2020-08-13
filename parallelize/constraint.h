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

  const std::shared_ptr<PacketDependency> get_dependency_compatible_with_packet(R3S::R3S_cfg_t cfg, R3S::R3S_packet_ast_t packet) const {
    std::shared_ptr<PacketDependency> compatible_dependency;
    R3S::Z3_ast pf_ast;

    for (auto dependency : dependencies) {
      if (dependency->should_ignore() || !dependency->is_rss_compatible())
        continue;

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

  friend std::ostream &operator<<(std::ostream &os,
                                  const Constraint &arg);
};
}
