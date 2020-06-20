#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <numeric>

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
    std::cerr << "[ERORR] Token not found." << '\n';
    std::cerr << "        Input:   " << line << '\n';
    std::cerr << "        Missing: " << token << std::endl;

    exit(1);
  }

  return std::istringstream(line.substr(found + token.length()));
}

void Parser::parse_access(std::vector<std::string> &state_content) {
  if (state_content.size() < 3) {
    std::cerr << "[ERROR] Missing parameters of access component" << std::endl;
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

void Parser::parse_constraint(std::vector<std::string> &state_content) {
  if (state_content.size() < 5) {
    std::cerr << "[ERROR] Missing parameters of constraint component"
              << std::endl;
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
    std::cerr << "[ERROR] Missing start statement on constraint component"
              << std::endl;
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
    std::cerr << "Error trying to open file." << std::endl;
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
}
}
