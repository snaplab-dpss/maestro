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

std::istringstream Parser::consume_token(std::string &line,
                                         const std::string &token) {
  auto found = line.find(token);

  if (found == std::string::npos) {

    Logger::error() << "Token not found" << "\n";
    Logger::error() << "Input:   " << line << "\n";
    Logger::error() << "Missing: " << token << "\n";

    exit(1);
  }

  return std::istringstream(line.substr(found + token.length()));
}

void Parser::parse_access(std::vector<std::string> &state_content) {
  if (state_content.size() < 3) {
    Logger::error() << "Missing parameters of access component" << "\n";
    exit(1);
  }

  unsigned int id;
  unsigned int device;
  unsigned int object;

  std::istringstream iss;

  iss = consume_token(state_content[0], Tokens::ID);
  iss >> std::ws >> id;

  iss = consume_token(state_content[1], Tokens::DEVICE);
  iss >> std::ws >> device;

  iss = consume_token(state_content[2], Tokens::OBJECT);
  iss >> std::ws >> object;

  state_content.erase(state_content.begin(), state_content.begin() + 3);

  if (state_content.size() == 0)
    return;

  LibvigAccess &access =
      get_or_push_unique_access(LibvigAccess(id, device, object));

  unsigned int layer;
  unsigned int protocol;

  iss = consume_token(state_content[0], Tokens::LAYER);
  iss >> std::ws >> layer;

  iss = consume_token(state_content[1], Tokens::PROTOCOL);
  iss >> std::ws >> protocol;

  state_content.erase(state_content.begin(), state_content.begin() + 2);

  for (auto &content : state_content) {
    unsigned int offset;

    iss = consume_token(content, Tokens::DEPENDENCY);
    iss >> std::ws >> offset;

    PacketDependency dependency(layer, protocol, offset);
    access.add_dependency(dependency);
  }
}

void Parser::report() {
  std::vector< std::pair<unsigned int, PacketDependencyIncompatible> > incompatible_dependency_id_pairs;

  for (const auto& access : accesses) {
    for (const auto& incompatible_dependency : access.get_dependencies_incompatible()) {
      std::pair<unsigned int, PacketDependencyIncompatible> pair(access.get_id(), incompatible_dependency);
      auto found_it = std::find(incompatible_dependency_id_pairs.begin(), incompatible_dependency_id_pairs.end(), pair);
      if (found_it != incompatible_dependency_id_pairs.end()) continue;
      if (incompatible_dependency.get_ignore()) continue;

      Logger::error() << "Incompatible dependency (access id ";
      Logger::error() << access.get_id();
      Logger::error() << "): ";
      Logger::error() << incompatible_dependency.get_description();
      Logger::error() << "\n";

      incompatible_dependency_id_pairs.push_back(pair);
    }
  }
}

void Parser::parse_constraint(std::vector<std::string> &state_content) {
  if (state_content.size() < 5) {
    Logger::error() << "Missing parameters of constraint component" << "\n";
    exit(1);
  }

  unsigned int first;
  unsigned int second;
  std::string expression;

  std::istringstream iss;

  iss = consume_token(state_content[0], Tokens::FIRST);
  iss >> std::ws >> first;

  iss = consume_token(state_content[1], Tokens::SECOND);
  iss >> std::ws >> second;

  if (state_content[2] != Tokens::STATEMENT_START) {
    Logger::error() << "Missing start statement of constraint component" << "\n";
    exit(1);
  }

  state_content.erase(state_content.begin(), state_content.begin() + 3);

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
  std::vector<std::string> state_content;

  while (getline(file, line)) {

    if (line == Tokens::ACCESS_END) {
      parse_access(state_content);
      state_content.clear();
      state = State::Init;
    } else if (line == Tokens::CONSTRAINT_END) {
      parse_constraint(state_content);
      state_content.clear();
      state = State::Init;
    } else if (line == Tokens::ACCESS_START) {
      state = State::Access;
    } else if (line == Tokens::CONSTRAINT_START) {
      state = State::Constraint;
    } else
      state_content.push_back(line);
  }

  file.close();

  report();
}

}
