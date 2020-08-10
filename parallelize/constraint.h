#pragma once

#include "libvig_access.h"

#include <iostream>
#include <vector>
#include <string>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class PacketFieldExpression {

private:
  R3S::Z3_context ctx;
  R3S::Z3_ast expression;
  unsigned int index;
  unsigned int packet_chunks_id;

public:
  PacketFieldExpression(const R3S::Z3_context &_ctx,
                        const R3S::Z3_ast &_expression,
                        const unsigned int &_index,
                        const unsigned int &_packet_chunks_id)
      : ctx(_ctx), expression(_expression), index(_index),
        packet_chunks_id(_packet_chunks_id) {}

  PacketFieldExpression(const PacketFieldExpression &pfe)
      : ctx(pfe.get_context()), expression(pfe.get_expression()),
        index(pfe.get_index()), packet_chunks_id(pfe.get_packet_chunks_id()) {}

  const R3S::Z3_context &get_context() const { return ctx; }
  const R3S::Z3_ast &get_expression() const { return expression; }
  const unsigned int &get_index() const { return index; }
  const unsigned int &get_packet_chunks_id() const { return packet_chunks_id; }

  friend bool operator<(const PacketFieldExpression &lhs,
                        const PacketFieldExpression &rhs);

  static void
  add_unique_packet_field_expression(std::vector<PacketFieldExpression> &pfes,
                                     const PacketFieldExpression &pfe);
  static const std::string PACKET_CHUNKS_NAME_PATTERN;
};

class Constraint {

private:
  R3S::Z3_context ctx;
  LibvigAccess first;
  LibvigAccess second;

  R3S::Z3_ast expression;
  std::pair<int, int> packet_chunks_ids_pair;
  std::vector<std::pair<PacketFieldExpression,
                        std::shared_ptr<const PacketDependency> > >
  packet_fields;

private:
  void generate_expression_from_read_args();
  void fill_packet_fields(R3S::Z3_ast &expression,
                          std::vector<PacketFieldExpression> &pfes);
  void zip_packet_fields_expression_and_values(
      const std::vector<PacketFieldExpression> &pfes);
  void check_incompatible_dependencies();

public:
  Constraint(const LibvigAccess &_first, const LibvigAccess &_second,
             const R3S::Z3_context &_ctx)
      : ctx(_ctx), first(_first), second(_second) {
    check_incompatible_dependencies();
    generate_expression_from_read_args();

    packet_chunks_ids_pair = std::pair<int, int>(-1, -1);

    std::vector<PacketFieldExpression> packet_fields_expressions;

    fill_packet_fields(expression, packet_fields_expressions);
    zip_packet_fields_expression_and_values(packet_fields_expressions);
  }

  Constraint(const Constraint &constraint)
      : ctx(constraint.get_context()), first(constraint.get_first_access()),
        second(constraint.get_second_access()),
        expression(constraint.get_expression()),
        packet_chunks_ids_pair(constraint.get_packet_chunks_ids_pair()) {

    for (const auto &packet_field : constraint.get_packet_fields()) {
      packet_fields.emplace_back(packet_field.first,
                                 packet_field.second->clone());
    }
  }

  const R3S::Z3_context &get_context() const { return ctx; }
  const LibvigAccess &get_first_access() const { return first; }
  const LibvigAccess &get_second_access() const { return second; }
  const R3S::Z3_ast &get_expression() const { return expression; }

  const std::pair<int, int> &get_packet_chunks_ids_pair() const {
    return packet_chunks_ids_pair;
  }
  const std::vector<std::pair<PacketFieldExpression,
                              std::shared_ptr<const PacketDependency> > > &
  get_packet_fields() const {
    return packet_fields;
  }

  R3S::Z3_ast &get_expression() { return expression; }
};
}
