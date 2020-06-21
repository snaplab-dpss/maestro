#include "logger.h"
#include "constraint.h"

#include <algorithm>
#include <iterator>

namespace ParallelSynthesizer {

bool operator==(const RawConstraint &lhs, const RawConstraint &rhs) {
  return lhs.first_access_id == rhs.first_access_id &&
         lhs.second_access_id == rhs.second_access_id &&
         lhs.expression == rhs.expression;
}

void PacketFieldExpression::add_unique_packet_field_expression(
    std::vector<PacketFieldExpression> &pfes,
    const PacketFieldExpression &pfe) {
  for (auto &stored_pfe : pfes) {
    if (Z3_is_eq_ast(pfe.get_context(), pfe.get_expression(),
                     stored_pfe.get_expression()))
      return;
  }

  pfes.push_back(pfe);
}

bool operator<(const PacketFieldExpression& lhs, const PacketFieldExpression& rhs) {
  return lhs.get_index() < rhs.get_index();
}

const std::string PacketFieldExpression::PACKET_CHUNKS_NAME_PATTERN = "packet_chunks_";

bool is_select_from_chunk(R3S::Z3_context &ctx, R3S::Z3_app &app, std::string& symbol_name) {
  R3S::Z3_func_decl app_decl = R3S::Z3_get_app_decl(ctx, app);
  R3S::Z3_symbol symbol_app_name = R3S::Z3_get_decl_name(ctx, app_decl);
  std::string app_name = R3S::Z3_get_symbol_string(ctx, symbol_app_name);

  if (app_name != "select")
    return false;

  R3S::Z3_ast array_ast = Z3_get_app_arg(ctx, app, 0);

  // TODO: assert(Z3_get_ast_kind(ctx, array_ast) == Z3_APP_AST);

  R3S::Z3_app array_app = R3S::Z3_to_app(ctx, array_ast);
  R3S::Z3_func_decl array_decl = R3S::Z3_get_app_decl(ctx, array_app);
  R3S::Z3_symbol symbol_array_name = R3S::Z3_get_decl_name(ctx, array_decl);
  
  symbol_name = R3S::Z3_get_symbol_string(ctx, symbol_array_name);

  auto found = symbol_name.find(PacketFieldExpression::PACKET_CHUNKS_NAME_PATTERN);
  return found != std::string::npos;
}

void Constraint::fill_packet_fields(R3S::Z3_ast &expr,
                                    std::vector<PacketFieldExpression> &pfes) {
  if (R3S::Z3_get_ast_kind(ctx, expr) != R3S::Z3_APP_AST)
    return;

  R3S::Z3_app app = R3S::Z3_to_app(ctx, expr);

  std::string symbol_name;
  if (is_select_from_chunk(ctx, app, symbol_name)) {
    R3S::Z3_ast index_ast = R3S::Z3_get_app_arg(ctx, app, 1);
    // TODO: assert(Z3_get_ast_kind(ctx, index_ast) == Z3_NUMERAL_AST);

    unsigned int index;
    R3S::Z3_get_numeral_uint(ctx, index_ast, &index);

    std::string packet_chunks_id_str = symbol_name.substr(PacketFieldExpression::PACKET_CHUNKS_NAME_PATTERN.size());
    unsigned int packet_chunks_id = std::stoi(packet_chunks_id_str); // int to unsigned int convertion, be carefull...

    PacketFieldExpression::add_unique_packet_field_expression(
        pfes, PacketFieldExpression(ctx, expr, index, packet_chunks_id));
    
    if (packet_chunks_ids_pair.first == -1) {
      packet_chunks_ids_pair = std::pair<int, int>(
        packet_chunks_id,
        packet_chunks_ids_pair.second
      );
    } else if (packet_chunks_ids_pair.second == -1 && packet_chunks_id != packet_chunks_ids_pair.first) {
      packet_chunks_ids_pair = std::pair<int, int>(
        packet_chunks_ids_pair.first,
        packet_chunks_id
      );
    }

    return;
  }

  unsigned int num_fields = R3S::Z3_get_app_num_args(ctx, app);
  for (unsigned int i = 0; i < num_fields; i++) {
    R3S::Z3_ast app_arg = R3S::Z3_get_app_arg(ctx, app, i);
    fill_packet_fields(app_arg, pfes);
  }
}

void Constraint::zip_packet_fields_expression_and_values(
    const std::vector<PacketFieldExpression>& pfes) {

  auto zipped_dependencies =
      LibvigAccess::zip_accesses_dependencies(first, second);

  auto pfes_sorted_copy = pfes;
  std::sort(pfes_sorted_copy.begin(), pfes_sorted_copy.end());

  auto zipped_dependencies_size = zipped_dependencies.size();

  if (zipped_dependencies_size != pfes_sorted_copy.size()) {
    Logger::error() << "zipped dependencies size different than the number of available packet fields "
                    << "(" << zipped_dependencies_size
                    << " != " << pfes_sorted_copy.size()
                    << ")" << "\n";
    exit(1);
  }

  for (auto i = 0; i < zipped_dependencies_size; i++) {
    bool inc = (i < zipped_dependencies_size - 1) &&
          (pfes_sorted_copy[i].get_index() < pfes_sorted_copy[i + 1].get_index());

    packet_fields.emplace_back(pfes_sorted_copy[i],
                               zipped_dependencies[i]);
  }
}

void Constraint::check_incompatible_dependencies() {
  if (first.get_dependencies_incompatible().size() ||
    second.get_dependencies_incompatible().size()) {
    Logger::error() << "Dependencies incompatible with RSS. Nothing we can do." << "\n";
    exit(1);
  }
}

}
