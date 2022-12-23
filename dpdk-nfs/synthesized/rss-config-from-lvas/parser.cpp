#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <numeric>

#include "logger.h"
#include "parser.h"

namespace ParallelSynthesizer {

LibvigAccess &Parser::get_or_push_unique_access(const LibvigAccess &access) {
  auto it = std::find(accesses.begin(), accesses.end(), access);

  if (it == accesses.end()) {
    accesses.emplace_back(access);
    return accesses.back();
  }

  return *it;
}

bool Parser::consume_token(const std::string &token, std::istringstream &iss,
                           bool optional) {
  assert(states.top().content.size());

  if (optional && last_loaded_content_type() != LoadedContentType::UNPARSED)
    return false;

  assert(last_loaded_content_type() == LoadedContentType::UNPARSED);

  auto line = last_loaded_content().unparsed.value;
  auto found = line.find(token);

  if (found == std::string::npos && !optional) {

    Logger::error() << "Token not found"
                    << "\n";
    Logger::error() << "Line:    " << line_counter << "\n";
    Logger::error() << "Input:   "
                    << "\"" << line << "\""
                    << "\n";
    Logger::error() << "Missing: "
                    << "\"" << token << "\""
                    << "\n";

    exit(1);
  } else if (found == std::string::npos) {
    return false;
  }

  line_counter++;
  consume_content();

  std::string consumed;
  if (optional) {
    auto optional_token_found =
        line.find(Tokens::OPTIONAL) != std::string::npos;
    consumed =
        line.substr(found + token.length() +
                    (optional_token_found ? Tokens::OPTIONAL.size() : 0));
  } else {
    consumed = line.substr(found + token.length());
  }
  iss = std::istringstream(consumed);

  return true;
}

void Parser::parse_access() {
  unsigned int id;
  unsigned int src_device;
  std::pair<bool, unsigned int> dst_device;
  std::pair<bool, bool> success;
  LibvigAccess::Operation operation;
  unsigned int object;

  std::istringstream iss;

  consume_token(Tokens::Access::START, iss);

  consume_token(Tokens::Access::ID, iss);
  iss >> std::ws >> id;

  consume_token(Tokens::Access::SRC_DEVICE, iss);
  iss >> std::ws >> src_device;

  dst_device.first = consume_token(Tokens::Access::DST_DEVICE, iss, true);
  if (dst_device.first) iss >> std::ws >> dst_device.second;

  success.first = consume_token(Tokens::Access::SUCCESS, iss, true);
  if (success.first) iss >> std::ws >> success.second;

  {
    std::string operation_str;
    consume_token(Tokens::Access::OPERATION, iss);
    iss >> std::ws >> operation_str;
    operation = LibvigAccess::parse_operation_token(operation_str);
  }

  consume_token(Tokens::Access::OBJECT, iss);
  iss >> std::ws >> object;

  LibvigAccess &access = get_or_push_unique_access(
      LibvigAccess(id, src_device, dst_device, success, operation, object));

  if (consume_token(Tokens::Access::END, iss, true)) {
    states.pop();
    return;
  }

  while (states.top().content.size()) {
    if (last_loaded_content_type() == LoadedContentType::ARGUMENT) {
      auto argument = last_loaded_content().argument.value;
      access.add_argument(argument);
    } else if (last_loaded_content_type() == LoadedContentType::METADATA) {
      auto metadata = last_loaded_content().metadata.value;
      access.add_metadata(metadata);
    } else
      break;

    consume_content();
  }

  consume_token(Tokens::Access::END, iss);
  states.pop();
}

void Parser::parse_argument() {
  LibvigAccessArgument::Type type;
  std::string expression;
  std::istringstream iss;

  consume_token(Tokens::Argument::START, iss);

  {
    std::string type_str;
    consume_token(Tokens::Argument::TYPE, iss);
    iss >> std::ws >> type_str;
    type = LibvigAccessArgument::parse_argument_type_token(type_str);
  }

  assert(last_loaded_content_type() == LoadedContentType::EXPRESSION);

  expression = last_loaded_content().expression.value;
  consume_content();

  LibvigAccessArgument argument(type, expression);

  if (states.top().content.size() &&
      last_loaded_content_type() == LoadedContentType::PACKET_DEPENDENCIES) {
    auto dependencies = last_loaded_content().dependencies.value;
    for (const auto &dependency : dependencies)
      argument.add_dependency(dependency.get());

    consume_content();
  }

  consume_token(Tokens::Argument::END, iss);

  states.pop();
  states.top().content.emplace_back(argument);
}

void Parser::parse_expression() {
  std::vector<std::string> fragments;
  std::istringstream iss;

  consume_token(Tokens::Expression::START, iss);

  while (states.top().content.size()) {
    assert(last_loaded_content_type() == LoadedContentType::UNPARSED);

    if (consume_token(Tokens::Expression::END, iss, true)) break;

    fragments.push_back(last_loaded_content().unparsed.value);
    consume_content();
  }

  states.pop();
  states.top().content.emplace_back(fragments);
}

void Parser::parse_packet_dependencies() {
  std::vector<std::shared_ptr<const Dependency> > dependencies;
  std::istringstream iss;

  consume_token(Tokens::PacketDependencies::START, iss);

  assert(states.top().content.size());

  while (states.top().content.size()) {
    if (last_loaded_content_type() != LoadedContentType::CHUNK) break;

    auto chunk = last_loaded_content().chunk.value;
    dependencies.push_back(chunk);

    consume_content();
  }

  consume_token(Tokens::PacketDependencies::END, iss);

  states.pop();
  states.top().content.emplace_back(dependencies);
}

void Parser::parse_chunk() {
  std::vector<std::shared_ptr<const Dependency> > dependencies;
  std::istringstream iss;

  unsigned int layer;
  std::pair<bool, unsigned int> protocol;

  consume_token(Tokens::Chunk::START, iss);

  consume_token(Tokens::Chunk::LAYER, iss);
  iss >> std::ws >> layer;

  protocol.first = consume_token(Tokens::Chunk::PROTOCOL, iss, true);
  if (protocol.first) iss >> std::ws >> protocol.second;

  while (states.top().content.size()) {
    unsigned int offset;

    if (!consume_token(Tokens::Chunk::DEPENDENCY, iss, true)) break;

    iss >> std::ws >> offset;

    PacketDependency dependency(layer, offset, protocol);
    dependencies.emplace_back(dependency.clone());
  }

  consume_token(Tokens::Chunk::END, iss);

  states.pop();

  for (const auto &dependency : dependencies) {
    states.top().content.emplace_back(dependency);
  }
}

void Parser::parse_metadata() {
  std::string interface;
  std::string file;
  std::istringstream iss;

  consume_token(Tokens::Metadata::START, iss);

  consume_token(Tokens::Metadata::INTERFACE, iss);
  iss >> std::ws >> interface;

  consume_token(Tokens::Metadata::FILE, iss);
  iss >> std::ws >> file;

  LibvigAccessMetadata metadata(interface, file);

  consume_token(Tokens::Metadata::END, iss);

  states.pop();
  states.top().content.emplace_back(metadata);
}

void Parser::parse_call_paths_constraint() {
  std::istringstream iss;
  std::string expression;

  consume_token(Tokens::CallPathConstraint::START, iss);

  assert(last_loaded_content_type() == LoadedContentType::EXPRESSION);

  expression = last_loaded_content().expression.value;
  consume_content();

  assert(last_loaded_content_type() == LoadedContentType::CALL_PATH_INFO);

  auto first_call_path_info = last_loaded_content().call_path_info.value;
  consume_content();

  assert(last_loaded_content_type() == LoadedContentType::CALL_PATH_INFO);

  auto second_call_path_info = last_loaded_content().call_path_info.value;
  consume_content();

  call_paths_constraints.emplace_back(expression, first_call_path_info,
                                      second_call_path_info);

  consume_token(Tokens::CallPathConstraint::END, iss);

  states.pop();
}

void Parser::parse_call_path_info() {
  std::istringstream iss;
  std::string call_path;
  CallPathInfo::Type type;
  std::pair<bool, unsigned int> id;

  consume_token(Tokens::CallPathInfo::START, iss);

  consume_token(Tokens::CallPathInfo::CALL_PATH, iss);
  iss >> std::ws >> call_path;

  {
    std::string type_str;
    consume_token(Tokens::CallPathInfo::TYPE, iss);
    iss >> std::ws >> type_str;
    type = CallPathInfo::parse_call_path_info_type_token(type_str);
  }

  id.first = false;
  if (consume_token(Tokens::CallPathInfo::ID, iss, true)) {
    iss >> std::ws >> id.second;
    id.first = true;
  }

  CallPathInfo call_path_info(call_path, type, id);

  if (states.top().content.size() &&
      last_loaded_content_type() == LoadedContentType::PACKET_DEPENDENCIES) {
    auto dependencies = last_loaded_content().dependencies.value;

    for (const auto &dependency : dependencies)
      call_path_info.add_dependency(dependency.get());

    consume_content();
  }

  consume_token(Tokens::CallPathInfo::END, iss);

  states.pop();
  states.top().content.emplace_back(call_path_info);
}

void Parser::parse(const std::string &filepath) {
  // TODO: deal with errors
  std::fstream file;
  std::string line;

  file.open(filepath.c_str(), std::ios::in);

  if (!file.is_open()) {
    Logger::error() << "Failed to open file"
                    << "\n";
    exit(1);
  }

  while (getline(file, line)) {

    if (line == Tokens::Access::START || line == Tokens::Argument::START ||
        line == Tokens::Expression::START ||
        line == Tokens::PacketDependencies::START ||
        line == Tokens::Chunk::START || line == Tokens::Metadata::START ||
        line == Tokens::CallPathConstraint::START ||
        line == Tokens::CallPathInfo::START) {
      states.emplace();
    }

    if (states.size() == 0) {
      Logger::error() << "Error while parsing \"" << line
                      << "\" (no loaded state)"
                      << "\n";
      exit(1);
    }

    states.top().content.emplace_back(line);

    if (line == Tokens::Access::END)
      parse_access();

    else if (line == Tokens::Argument::END)
      parse_argument();

    else if (line == Tokens::Expression::END)
      parse_expression();

    else if (line == Tokens::PacketDependencies::END)
      parse_packet_dependencies();

    else if (line == Tokens::Chunk::END)
      parse_chunk();

    else if (line == Tokens::Metadata::END)
      parse_metadata();

    else if (line == Tokens::CallPathInfo::END)
      parse_call_path_info();

    else if (line == Tokens::CallPathConstraint::END)
      parse_call_paths_constraint();
  }

  file.close();
}
}
