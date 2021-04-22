#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include <algorithm>
#include <assert.h>

namespace R3S {
#include <r3s.h>
}

#include "logger.h"
#include "tokens.h"
#include "dependency.h"

namespace ParallelSynthesizer {

class LibvigAccessMetadata {
private:
  std::string interface;
  std::string file;

public:
  LibvigAccessMetadata() {}

  LibvigAccessMetadata(const std::string &_interface, const std::string _file)
      : interface(_interface), file(_file) {}

  LibvigAccessMetadata(const LibvigAccessMetadata &metadata)
      : LibvigAccessMetadata(metadata.interface, metadata.file) {}

  const std::string &get_interface() const { return interface; }
  const std::string &get_file() const { return file; }

  std::string get_data_structure() const {
    auto delim = interface.find("_");
    assert(delim != std::string::npos);
    return interface.substr(0, delim);
  }

  friend std::ostream &operator<<(std::ostream &os,
                                  const LibvigAccessMetadata &arg);
};

class LibvigAccessArgument {
public:
  enum Type {
    READ,
    WRITE,
    RESULT
  };

  static Type parse_argument_type_token(std::string arg_type) {
    if (arg_type == Tokens::ArgumentType::READ)
      return READ;
    if (arg_type == Tokens::ArgumentType::WRITE)
      return WRITE;
    if (arg_type == Tokens::ArgumentType::RESULT)
      return RESULT;

    Logger::error() << "Invalid argument type token \"";
    Logger::error() << arg_type;
    Logger::error() << "\n";

    exit(1);
  }

private:
  Type type;
  std::string expression;
  DependencyManager dependencies;

public:
  LibvigAccessArgument(const Type &_type, std::string _expr)
      : type(_type), expression(_expr) {}

  LibvigAccessArgument(const LibvigAccessArgument &argument)
      : type(argument.type), expression(argument.expression), dependencies(argument.dependencies) {}

  LibvigAccessArgument::Type get_type() const { return type; }
  const std::string &get_expression() const { return expression; }

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
                                  const LibvigAccessArgument &arg);

  friend bool operator==(const LibvigAccessArgument &lhs,
                         const LibvigAccessArgument &rhs);
};

class LibvigAccess {
public:
  enum Operation {
    READ,
    WRITE,
    NOP,
    INIT,
    CREATE,
    VERIFY,
    UPDATE,
    DESTROY
  };

private:
  unsigned int id;
  unsigned int src_device;
  std::pair<bool, unsigned int> dst_device;
  std::pair<bool, bool> success;
  Operation operation;
  unsigned int object;

  std::vector<LibvigAccessArgument> arguments;
  std::pair<bool, LibvigAccessMetadata> metadata;

public:
  LibvigAccess(const unsigned int &_id, const unsigned int &_src_device,
               const std::pair<bool, unsigned int> _dst_device,
               const std::pair<bool, bool> _success,
               const Operation &_operation, const unsigned int &_object)
      : id(_id), src_device(_src_device), dst_device(_dst_device),
        success(_success),
        operation(_operation), object(_object) {
    metadata.first = false;
  }

  LibvigAccess(const LibvigAccess &access)
      : id(access.id), src_device(access.src_device), dst_device(access.dst_device),
        success(access.success), operation(access.operation), object(access.object),
        arguments(access.arguments), metadata(access.metadata) {}

  const unsigned int &get_id() const { return id; }
  const unsigned int &get_src_device() const { return src_device; }
  const unsigned int &get_dst_device() const {
    assert(dst_device.first);
    return dst_device.second;
  }
  bool get_success() const {
    assert(success.first);
    return success.second;
  }
  const Operation &get_operation() const { return operation; }
  const unsigned int &get_object() const { return object; }
  const std::vector<LibvigAccessArgument> &get_arguments() const {
    return arguments;
  }
  const LibvigAccessMetadata &get_metadata() const {
    assert(metadata.first);
    return metadata.second;
  }

  bool is_dst_device_set() const { return dst_device.first; }
  bool is_success_set() const { return success.first; }
  bool is_metadata_set() const { return metadata.first; }

  bool are_dst_devices_equal(const LibvigAccess& other) const {
    return dst_device == other.dst_device;
  }

  bool has_argument(const LibvigAccessArgument::Type &type) const;
  const LibvigAccessArgument& get_argument(const LibvigAccessArgument::Type &type) const;

  void add_argument(const LibvigAccessArgument &argument) {
    arguments.emplace_back(argument);
  }

  void add_metadata(const LibvigAccessMetadata &_metadata) {
    metadata = std::make_pair(true, _metadata);
  }

  friend std::ostream &operator<<(std::ostream &os, const LibvigAccess &access);
  friend bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs);

  static bool content_equal(const LibvigAccess &access1,
                            const LibvigAccess &access2);

  static Operation parse_operation_token(std::string operation) {
    if (operation == Tokens::Operations::WRITE) {
      return Operation::WRITE;
    }

    if (operation == Tokens::Operations::READ) {
      return Operation::READ;
    }

    if (operation == Tokens::Operations::NOP) {
      return Operation::NOP;
    }

    if (operation == Tokens::Operations::INIT) {
      return Operation::INIT;
    }

    if (operation == Tokens::Operations::CREATE) {
      return Operation::CREATE;
    }

    if (operation == Tokens::Operations::VERIFY) {
      return Operation::VERIFY;
    }

    if (operation == Tokens::Operations::UPDATE) {
      return Operation::UPDATE;
    }

    if (operation == Tokens::Operations::DESTROY) {
      return Operation::DESTROY;
    }

    Logger::error() << "Invalid operation token \"";
    Logger::error() << operation;
    Logger::error() << "\"\n";

    exit(1);
  }
};

} // namespace ParallelSynthesizer
