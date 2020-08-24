#include "logger.h"
#include "constraint.h"

#include <algorithm>
#include <iterator>

namespace ParallelSynthesizer {

R3S::Z3_ast Constraint::parse_expr(R3S::Z3_context ctx, const std::string& expr_str) {
  auto expr = R3S::Z3_parse_smtlib2_string(ctx, expr_str.c_str(), 0, 0, 0, 0, 0, 0);

  assert(R3S::Z3_get_ast_kind(ctx, expr) == R3S::Z3_APP_AST);

  R3S::Z3_app app = R3S::Z3_to_app(ctx, expr);

  R3S::Z3_func_decl app_decl = R3S::Z3_get_app_decl(ctx, app);
  R3S::Z3_symbol symbol_app_name = R3S::Z3_get_decl_name(ctx, app_decl);
  std::string app_name = R3S::Z3_get_symbol_string(ctx, symbol_app_name);

  assert(app_name == "=");
  assert(R3S::Z3_get_app_num_args(ctx, app) == 2);

  R3S::Z3_ast app_arg = R3S::Z3_get_app_arg(ctx, app, 1);

  return app_arg;
}

bool operator==(const PacketDependenciesExpression &lhs, const PacketDependenciesExpression& rhs) {
  return R3S::Z3_is_eq_ast(lhs.ctx, lhs.expression, rhs.expression);
}

bool operator<(const PacketDependenciesExpression &lhs,
               const PacketDependenciesExpression &rhs) {
  return lhs.get_index() < rhs.get_index();
}

std::ostream &operator<<(std::ostream &os,
                         const PacketDependenciesExpression &arg) {
  os << "  expression    ";
  os << R3S::Z3_ast_to_string(arg.ctx, arg.expression);
  os << "\n";

  os << "  index         ";
  os << arg.index;
  os << "\n";

  os << "  chunk id      ";
  os << arg.packet_chunks_id;
  os << "\n";

  os << "  dependencies: ";
  os << "\n";

  if (arg.dependencies.size()) {
    for (const auto& dependency : arg.dependencies) {
      os << "    " << *dependency;
      os << "\n";
    }
  }

  return os;
}

std::ostream &operator<<(std::ostream &os,
                         const Constraint &arg) {
  os << "================ CONSTRAINT ================";
  os << "\n";

  os << "first access id  ";
  os << arg.first.get_id();
  os << "\n";

  os << "first chunk id   ";
  os << arg.packet_chunks_ids.first;
  os << "\n";

  os << "second access id ";
  os << arg.second.get_id();
  os << "\n";

  os << "second chunk id  ";
  os << arg.packet_chunks_ids.second;
  os << "\n";

  os << "expression       ";
  os << R3S::Z3_ast_to_string(arg.ctx, arg.expression);
  os << "\n";

  if (arg.packet_dependencies_expressions.size()) {
    os << "expressions:";
    os << "\n";
    for (const auto& packet_dependency_expression : arg.packet_dependencies_expressions) {
      os << packet_dependency_expression;
      os << "\n";
    }
  }

  os << "===========================================";
  os << "\n";

  return os;
}

const std::string PacketDependenciesExpression::PACKET_CHUNKS_NAME_PATTERN =
    "packet_chunks__ref_";

void Constraint::generate_expression_from_read_args() {
  assert(first.has_argument(LibvigAccessArgument::Type::READ));
  assert(second.has_argument(LibvigAccessArgument::Type::READ));

  auto first_read_arg = first.get_argument(LibvigAccessArgument::Type::READ);
  auto second_read_arg = second.get_argument(LibvigAccessArgument::Type::READ);

  auto first_expr_str = first_read_arg.get_expression();
  auto second_expr_str = second_read_arg.get_expression();

  auto first_expr = Constraint::parse_expr(ctx, first_expr_str);
  auto second_expr = Constraint::parse_expr(ctx, second_expr_str);

  expression = R3S::Z3_simplify(ctx, R3S::Z3_mk_eq(ctx, first_expr, second_expr));
}

void Constraint::store_unique_packet_dependencies_expression(const PacketDependenciesExpression& pde) {
  auto found_it = std::find(packet_dependencies_expressions.begin(), packet_dependencies_expressions.end(), pde);

  if (found_it == packet_dependencies_expressions.end())
    packet_dependencies_expressions.push_back(pde);
}

bool is_select_from_chunk(R3S::Z3_context &ctx, R3S::Z3_app &app,
                          std::string &symbol_name) {
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

  auto found =
      symbol_name.find(PacketDependenciesExpression::PACKET_CHUNKS_NAME_PATTERN);
  return found != std::string::npos;
}

void Constraint::fill_packet_fields(R3S::Z3_ast &expr) {
  if (R3S::Z3_get_ast_kind(ctx, expr) != R3S::Z3_APP_AST)
    return;

  R3S::Z3_app app = R3S::Z3_to_app(ctx, expr);

  std::string symbol_name;
  if (is_select_from_chunk(ctx, app, symbol_name)) {
    R3S::Z3_ast index_ast = R3S::Z3_get_app_arg(ctx, app, 1);
    // TODO: assert(Z3_get_ast_kind(ctx, index_ast) == Z3_NUMERAL_AST);

    unsigned int index;
    R3S::Z3_get_numeral_uint(ctx, index_ast, &index);

    std::string packet_chunks_id_str = symbol_name.substr(
        PacketDependenciesExpression::PACKET_CHUNKS_NAME_PATTERN.size());

    // int to unsigned int convertion, be carefull...
    unsigned int packet_chunks_id = std::stoi(packet_chunks_id_str);

    PacketDependenciesExpression pde(ctx, expr, index, packet_chunks_id);
    store_unique_packet_dependencies_expression(pde);

    if (packet_chunks_ids.first == -1) {
      packet_chunks_ids = std::make_pair(packet_chunks_id, packet_chunks_ids.second);
    }

    else if (packet_chunks_ids.second == -1 &&
               packet_chunks_id != packet_chunks_ids.first) {
      packet_chunks_ids = std::make_pair(packet_chunks_ids.first, packet_chunks_id);
    }

    return;
  }

  unsigned int num_fields = R3S::Z3_get_app_num_args(ctx, app);
  for (unsigned int i = 0; i < num_fields; i++) {
    R3S::Z3_ast app_arg = R3S::Z3_get_app_arg(ctx, app, i);
    fill_packet_fields(app_arg);
  }
}

void Constraint::zip_packet_fields_expression_and_values() {
  assert(first.has_argument(LibvigAccessArgument::Type::READ));
  assert(second.has_argument(LibvigAccessArgument::Type::READ));

  auto first_read_arg = first.get_argument(LibvigAccessArgument::Type::READ);
  auto second_read_arg = second.get_argument(LibvigAccessArgument::Type::READ);

  auto first_read_arg_copy = first_read_arg;
  auto second_read_arg_copy = second_read_arg;

  first_read_arg_copy.sort_dependencies();
  second_read_arg_copy.sort_dependencies();

  const auto &first_deps = first_read_arg_copy.get_dependencies().get();
  const auto &second_deps = second_read_arg_copy.get_dependencies().get();

  int smaller_packet_chunks_id = -1;

  for (const auto &pde : packet_dependencies_expressions) {
    const auto &id = pde.get_packet_chunks_id();
    if (id == smaller_packet_chunks_id)
      continue;

    if (smaller_packet_chunks_id == -1 || smaller_packet_chunks_id > id)
      smaller_packet_chunks_id = id;

    break;
  }

  std::sort(packet_dependencies_expressions.begin(), packet_dependencies_expressions.end());

  if (first_deps.size() + second_deps.size() < packet_dependencies_expressions.size()) {

    Logger::error() << "\n";
    Logger::error() << "Total number of dependencies is different than ";
    Logger::error()
        << "total number of available expressions of packet fields.";
    Logger::error() << "\n";

    Logger::error()
        << "This is most likely caused by RSS incompatible packet fields.";
    Logger::error() << "\n";

    Logger::error() << "\n";
    Logger::error() << "First access:";
    Logger::error() << "\n";
    Logger::error() << first;
    Logger::error() << "\n";

    Logger::error() << "\n";
    Logger::error() << "Second access:";
    Logger::error() << "\n";
    Logger::error() << second;
    Logger::error() << "\n";

    Logger::error() << "\n";
    Logger::error() << "Available expressions of packet fields";
    Logger::error() << " (";
    Logger::error() << packet_dependencies_expressions.size();
    Logger::error() << "):";
    Logger::error() << "\n";

    for (const auto &pde : packet_dependencies_expressions) {
      Logger::error() << "  ";
      Logger::error() << R3S::Z3_ast_to_string(
                             pde.get_context(),
                             pde.get_expression());
      Logger::error() << "\n";
    }

    exit(1);
  }

  unsigned int first_counter = 0;
  unsigned int second_counter = 0;

  for (auto &pde : packet_dependencies_expressions) {
    const PacketDependency *prev_packet_dependency = nullptr;

    for (;;) {
      const PacketDependency *curr_packet_dependency = nullptr;

      if (pde.get_packet_chunks_id() == smaller_packet_chunks_id) {
        if(first_counter >= first_deps.size()) break;

        assert(first_deps[first_counter]->is_packet_related());

        curr_packet_dependency = dynamic_cast<const PacketDependency *>(
              first_deps[first_counter].get());

        if (prev_packet_dependency && (
              prev_packet_dependency->get_layer() != curr_packet_dependency->get_layer() ||
              prev_packet_dependency->get_offset() != curr_packet_dependency->get_offset())) break;

        first_counter++;
      }

      else {
        if(second_counter >= second_deps.size()) break;

        assert(second_deps[second_counter]->is_packet_related());

        curr_packet_dependency = dynamic_cast<const PacketDependency *>(
              second_deps[second_counter].get());

        if (prev_packet_dependency && (
              prev_packet_dependency->get_layer() != curr_packet_dependency->get_layer() ||
              prev_packet_dependency->get_offset() != curr_packet_dependency->get_offset())) break;

        second_counter++;
      }

      assert(curr_packet_dependency);

      pde.store_dependency(curr_packet_dependency);
      prev_packet_dependency = curr_packet_dependency;

    }
  }
}

void Constraint::check_incompatible_dependencies() {
  assert(first.has_argument(LibvigAccessArgument::Type::READ));
  assert(second.has_argument(LibvigAccessArgument::Type::READ));

  auto first_read_arg = first.get_argument(LibvigAccessArgument::Type::READ);
  auto second_read_arg = first.get_argument(LibvigAccessArgument::Type::READ);

  const auto &first_dependencies = first_read_arg.get_dependencies().get();
  const auto &second_dependencies = second_read_arg.get_dependencies().get();

  auto incompatible_dependency_filter = [](
      const std::shared_ptr<const Dependency> & dependency)->bool {
    if (dependency->should_ignore())
      return false;
    return !dependency->is_rss_compatible();
  };

  auto first_it =
      std::find_if(first_dependencies.begin(), first_dependencies.end(),
                   incompatible_dependency_filter);
  auto second_it =
      std::find_if(second_dependencies.begin(), second_dependencies.end(),
                   incompatible_dependency_filter);

  if (first_it != first_dependencies.end() ||
      second_it != second_dependencies.end()) {
    Logger::error() << "Dependencies incompatible with RSS. Nothing we can do."
                    << "\n";
    exit(0);
  }
}

std::ostream &operator<<(std::ostream &os,
                         const CallPathInfo &arg) {
  os << "call path info";
  os << "\n";

  os << "  call path ";
  os << arg.call_path;
  os << "\n";

  os << "  symbol    ";
  os << arg.symbol;
  os << "\n";

  os << "  type      ";
  if (arg.type == CallPathInfo::Type::SOURCE)
    os << "source";
  else if (arg.type == CallPathInfo::Type::PAIR)
    os << "pair";
  os << "\n";

  os << arg.dependencies;

  return os;
}

std::ostream &operator<<(std::ostream &os,
                         const CallPathsConstraint &arg) {
  os << "================ CALL PATHS CONSTRAINT ================";
  os << "\n";

  os << "expression  " << arg.expression_str;
  os << "\n";

  os << arg.first;
  os << arg.second;

  os << "=======================================================";
  os << "\n";

  return os;
}

}
