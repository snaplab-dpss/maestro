#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <numeric>

#include "logger.h"
#include "parser.h"

namespace ParallelSynthesizer {

enum State {
  Init,
  Access,
  Constraint,
  Statement
};

LibvigAccess &Parser::get_or_push_unique_access(const LibvigAccess &access) {
  auto it = std::find(accesses.begin(), accesses.end(), access);

  if (it == accesses.end()) {
    accesses.emplace_back(access);
    return accesses.back();
  }

  return *it;
}

void Parser::push_unique_raw_constraint(const RawConstraint &raw_constraint) {
  auto it =
      std::find(raw_constraints.begin(), raw_constraints.end(), raw_constraint);

  if (it == raw_constraints.end())
    raw_constraints.push_back(raw_constraint);
}

std::istringstream Parser::consume_token(const std::string &token) {
  assert(state_content.size());

  auto line = *state_content.begin();
  auto found = line.find(token);

  line_counter++;
  state_content.erase(state_content.begin());

  if (found == std::string::npos) {

    Logger::error() << "Token not found";
    Logger::error() << "\n";
    Logger::error() << "Line:    " << line_counter;
    Logger::error() << "\n";
    Logger::error() << "Input:   \"" << line << "\"";
    Logger::error() << "\n";
    Logger::error() << "Missing: \"" << token << "\"";
    Logger::error() << "\n";

    exit(1);
  }

  return std::istringstream(line.substr(found + token.length()));
}

void Parser::parse_access() {
  if (state_content.size() < 3) {
    Logger::error() << "Missing parameters of access component" << "\n";
    exit(1);
  }

  unsigned int id;
  unsigned int device;
  unsigned int object;
  std::string operation;

  std::istringstream iss;

  iss = consume_token(Tokens::ID);
  iss >> std::ws >> id;

  iss = consume_token(Tokens::DEVICE);
  iss >> std::ws >> device;

  iss = consume_token(Tokens::OBJECT);
  iss >> std::ws >> object;

  iss = consume_token(Tokens::OPERATION);
  iss >> std::ws >> operation;

  auto operation_parsed = LibvigAccess::parse_operation_token(operation);

  LibvigAccess &access =
      get_or_push_unique_access(LibvigAccess(id, device, object, operation_parsed));

  if (state_content.size() == 0)
    return;

  unsigned int layer;
  unsigned int protocol;

  iss = consume_token(Tokens::LAYER);
  iss >> std::ws >> layer;

  iss = consume_token(Tokens::PROTOCOL);
  iss >> std::ws >> protocol;

  while (state_content.size()) {
    unsigned int offset;

    iss = consume_token(Tokens::DEPENDENCY);
    iss >> std::ws >> offset;

    PacketDependency dependency(layer, protocol, offset);
    access.add_dependency(dependency.get_unique().get());
  }
}

void Parser::report() {
  std::vector< std::pair<unsigned int, PacketDependencyIncompatible> > incompatible_dependency_id_pairs;

  for (const auto& access : accesses) {
    for (const auto& dependency : access.get_dependencies()) {

      if (dependency->is_rss_compatible() || dependency->should_ignore())
        continue;

      const auto& incompatible = dynamic_cast<const PacketDependencyIncompatible&>(*dependency);

      std::pair<unsigned int, PacketDependencyIncompatible> pair(access.get_id(), incompatible);
      auto found_it = std::find(incompatible_dependency_id_pairs.begin(), incompatible_dependency_id_pairs.end(), pair);
      if (found_it != incompatible_dependency_id_pairs.end()) continue;

      Logger::error() << "=============== Incompatible dependency in access ===============";
      Logger::error() << "\n";
      Logger::error() << "Access:";
      Logger::error() << "\n";
      Logger::error() << access;
      Logger::error() << "\n";
      Logger::error() << "=================================================================";
      Logger::error() << "\n";
      Logger::error() << "\n";

      incompatible_dependency_id_pairs.push_back(pair);
    }
  }
}

void Parser::parse_constraint() {
  if (state_content.size() < 5) {
    Logger::error() << "Missing parameters of constraint component" << "\n";
    exit(1);
  }

  unsigned int first;
  unsigned int second;
  std::string expression;

  std::istringstream iss;

  iss = consume_token(Tokens::FIRST);
  iss >> std::ws >> first;

  iss = consume_token(Tokens::SECOND);
  iss >> std::ws >> second;

  consume_token(Tokens::STATEMENT_START);

  expression = std::accumulate(state_content.begin(), state_content.end() - 1,
                               std::string(""));

  RawConstraint raw_constraint(first, second, expression);
  push_unique_raw_constraint(raw_constraint);
}

void Parser::parse(std::string filepath) {
  // TODO: deal with errors
  std::fstream file;

  file.open(filepath.c_str(), std::ios::in);

  if (!file.is_open()) {
    Logger::error() << "Failed to open file" << "\n";
    exit(1);
  }

  std::string line;
  State state(State::Init);

  while (getline(file, line)) {

    if (line == Tokens::ACCESS_END) {
      parse_access();
      state_content.clear();

      line_counter++;
      state = State::Init;
    } else if (line == Tokens::CONSTRAINT_END) {
      parse_constraint();
      state_content.clear();

      line_counter++;
      state = State::Init;
    } else if (line == Tokens::ACCESS_START) {
      line_counter++;
      state = State::Access;
    } else if (line == Tokens::CONSTRAINT_START) {
      line_counter++;
      state = State::Constraint;
    } else {
      state_content.push_back(line);
    }
  }

  file.close();

  report();
}

}
