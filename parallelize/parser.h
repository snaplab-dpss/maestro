#pragma once

#include "libvig_access.h"
#include "constraint.h"
#include "tokens.h"

#include <vector>
#include <stack>
#include <deque>
#include <numeric>

namespace ParallelSynthesizer {

class Parser {
public:
  enum LoadedContentType {
    UNPARSED,
    ACCESS,
    ARGUMENT,
    PACKET_DEPENDENCIES,
    CHUNK,
    METADATA,
    EXPRESSION,
    CALL_PATHS_CONSTRAINT,
    CALL_PATH_INFO
  };

  union LoadedContent {

    struct unparsed_t {
      LoadedContentType type;
      std::string value;
    } unparsed;

    struct access_t {
      LoadedContentType type;
      LibvigAccess value;
    } access;

    struct argument_t {
      LoadedContentType type;
      LibvigAccessArgument value;
    } argument;

    struct expression_t {
      LoadedContentType type;
      std::string value;
    } expression;

    struct chunk_t {
      LoadedContentType type;
      std::shared_ptr<const Dependency> value;
    } chunk;

    struct dependencies_t {
      LoadedContentType type;
      std::vector<std::shared_ptr<const Dependency> > value;
    } dependencies;

    struct metadata_t {
      LoadedContentType type;
      LibvigAccessMetadata value;
    } metadata;

    struct call_paths_constraint_t {
      LoadedContentType type;
      CallPathsConstraint value;
    } call_paths_constraint;

    struct call_path_info_t {
      LoadedContentType type;
      CallPathInfo value;
    } call_path_info;

    LoadedContent(const std::string &_unparsed)
        : unparsed{ UNPARSED, std::move(_unparsed) } {}

    LoadedContent(const LibvigAccess &_access) : access{ ACCESS, _access } {}

    LoadedContent(const LibvigAccessArgument &_arg)
        : argument{ ARGUMENT, _arg } {}

    LoadedContent(const std::vector<std::string> &fragments) {
      std::string _expression;

      for (auto frag : fragments) {
        frag.erase(frag.begin(),
                   std::find_if(frag.begin(), frag.end(),
                                [](int ch) { return !std::isspace(ch); }));

        frag.erase(std::find_if(frag.rbegin(), frag.rend(), [](int ch) {
                                  return !std::isspace(ch);
                                }).base(),
                   frag.end());

        _expression += frag + " ";
      }

      expression.type = EXPRESSION;
      new ((void *)(&expression.value)) std::string(_expression);
    }

    LoadedContent(
        const std::vector<std::shared_ptr<const Dependency> > &_dependencies)
        : dependencies{ PACKET_DEPENDENCIES, _dependencies } {}

    LoadedContent(std::shared_ptr<const Dependency> _chunk)
        : chunk{ CHUNK, _chunk } {}

    LoadedContent(const LibvigAccessMetadata &_metadata)
        : metadata{ METADATA, _metadata } {}

    LoadedContent(const CallPathsConstraint &_call_paths_constraint)
        : call_paths_constraint{ CALL_PATHS_CONSTRAINT, _call_paths_constraint } {}

    LoadedContent(const CallPathInfo &_call_path_info)
        : call_path_info{ CALL_PATH_INFO, _call_path_info } {}

    LoadedContent(const LoadedContent &other) {
      switch (unparsed.type) {
        case UNPARSED:
          ::new (&unparsed) auto(other.unparsed);
          break;
        case ACCESS:
          ::new (&access) auto(other.access);
          break;
        case ARGUMENT:
          ::new (&argument) auto(other.argument);
          break;
        case EXPRESSION:
          ::new (&expression) auto(other.expression);
          break;
        case CHUNK:
          ::new (&chunk) auto(other.chunk);
          break;
        case PACKET_DEPENDENCIES:
          ::new (&dependencies) auto(other.dependencies);
          break;
        case METADATA:
          ::new (&metadata) auto(other.metadata);
          break;
        case CALL_PATHS_CONSTRAINT:
          ::new (&call_paths_constraint) auto(other.call_paths_constraint);
          break;
        case CALL_PATH_INFO:
          ::new (&call_path_info) auto(other.call_path_info);
          break;
      }
    }

    LoadedContent &operator=(LoadedContent other) {
      switch (other.unparsed.type) {
        case UNPARSED:
          unparsed.type = other.unparsed.type;
          unparsed.value = other.unparsed.value;
          break;
        case ACCESS:
          access.type = other.access.type;
          access.value = other.access.value;
          break;
        case ARGUMENT:
          argument.type = other.argument.type;
          argument.value = other.argument.value;
          break;
        case EXPRESSION:
          expression.type = other.expression.type;
          expression.value = other.expression.value;
          break;
        case CHUNK:
          chunk.type = other.chunk.type;
          chunk.value = other.chunk.value;
          break;
        case PACKET_DEPENDENCIES:
          dependencies.type = other.dependencies.type;
          dependencies.value = other.dependencies.value;
          break;
        case METADATA:
          metadata.type = other.metadata.type;
          metadata.value = other.metadata.value;
          break;
        case CALL_PATHS_CONSTRAINT:
          call_paths_constraint.type = other.call_paths_constraint.type;
          call_paths_constraint.value = other.call_paths_constraint.value;
          break;
        case CALL_PATH_INFO:
          call_path_info.type = other.call_path_info.type;
          call_path_info.value = other.call_path_info.value;
          break;
      }
      return *this;
    }

    ~LoadedContent() {
      switch (unparsed.type) {
        case UNPARSED:
          unparsed.~unparsed_t();
          break;
        case ACCESS:
          access.~access_t();
          break;
        case ARGUMENT:
          argument.~argument_t();
          break;
        case EXPRESSION:
          expression.~expression_t();
          break;
        case CHUNK:
          chunk.~chunk_t();
          break;
        case PACKET_DEPENDENCIES:
          dependencies.~dependencies_t();
          break;
        case METADATA:
          metadata.~metadata_t();
          break;
        case CALL_PATHS_CONSTRAINT:
          call_paths_constraint.~call_paths_constraint_t();
          break;
        case CALL_PATH_INFO:
          call_path_info.~call_path_info_t();
          break;
      }
    }
  };

  class Content {
  private:
    LoadedContent content;

  public:
    Content(const std::string &_unparsed) : content(std::move(_unparsed)) {}

    Content(const LibvigAccess &_access) : content(_access) {}

    Content(const LibvigAccessArgument &_arg) : content(_arg) {}

    Content(const std::vector<std::string> &fragments)
        : content(std::move(fragments)) {}

    Content(
        const std::vector<std::shared_ptr<const Dependency> > &_dependencies)
        : content(_dependencies) {}

    Content(std::shared_ptr<const Dependency> _chunk) : content(_chunk) {}

    Content(const LibvigAccessMetadata &_metadata) : content(_metadata) {}

    Content(const CallPathsConstraint &_call_paths_constraint) : content(_call_paths_constraint) {}

    Content(const CallPathInfo &_call_path_info) : content(_call_path_info) {}

    Content(const Content &_content) : content(_content.content) {}

    Content &operator=(Content other) {
      content = LoadedContent(other.content);
      return *this;
    }

    const LoadedContent &get_content() const { return content; }
    const LoadedContentType &get_loaded_type() const {
      return content.unparsed.type;
    }
  };

  struct State {
    std::deque<Content> content;

    void debug() {
      Logger::debug() << "======== CONTENT ========";
      Logger::debug() << "\n";
      for (const auto &c : content) {
        switch (c.get_loaded_type()) {
          case UNPARSED:
            Logger::debug() << "UNPARSED [ ";
            Logger::debug() << c.get_content().unparsed.value;
            Logger::debug() << " ]";
            break;
          case ACCESS:
            Logger::debug() << "ACCESS";
            break;
          case ARGUMENT:
            Logger::debug() << "ARGUMENT";
            break;
          case EXPRESSION:
            Logger::debug() << "EXPRESSION";
            break;
          case CHUNK:
            Logger::debug() << "CHUNK";
            break;
          case PACKET_DEPENDENCIES:
            Logger::debug() << "PACKET_DEPENDENCIES";
            break;
          case METADATA:
            Logger::debug() << "METADATA";
            break;
          case CALL_PATHS_CONSTRAINT:
            Logger::debug() << "CALL_PATHS_CONSTRAINT";
            break;
          case CALL_PATH_INFO:
            Logger::debug() << "CALL_PATH_INFO";
            break;
        }
        Logger::debug() << "\n";
      }
      Logger::debug() << "=========================";
      Logger::debug() << "\n";
    }
  };

private:
  std::stack<State> states;
  unsigned line_counter;

  std::vector<LibvigAccess> accesses;
  std::vector<CallPathsConstraint> call_paths_constraints;

private:
  LibvigAccess &get_or_push_unique_access(const LibvigAccess &access);

  bool consume_token(const std::string &token, std::istringstream &iss,
                     bool optional = false);

  void consume_content() {
    assert(states.size());
    assert(states.top().content.size());
    states.top().content.pop_front();
  }

  const LoadedContentType &last_loaded_content_type() const {
    assert(states.size());
    assert(states.top().content.size());
    return states.top().content[0].get_loaded_type();
  }

  const LoadedContent &last_loaded_content() const {
    assert(states.size());
    assert(states.top().content.size());
    return states.top().content[0].get_content();
  }

  void parse_access();
  void parse_argument();
  void parse_expression();
  void parse_packet_dependencies();
  void parse_chunk();
  void parse_metadata();
  void parse_call_paths_constraint();
  void parse_call_path_info();

public:
  Parser(const std::string &filepath) : line_counter(0) { parse(filepath); }

  const std::vector<LibvigAccess> &get_accesses() const { return accesses; }
  const std::vector<CallPathsConstraint> &get_call_paths_constraints() const { return call_paths_constraints; }

  void parse(const std::string &filepath);
};
}
