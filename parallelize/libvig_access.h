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

  LibvigAccessMetadata(const std::string& _interface, const std::string _file)
    : interface(_interface), file(_file) {}

  LibvigAccessMetadata(const LibvigAccessMetadata& metadata)
    : LibvigAccessMetadata(metadata.interface, metadata.file) {}

  const std::string& get_interface() const { return interface; }
  const std::string& get_file() const { return file; }

  friend std::ostream& operator<<(std::ostream& os, const LibvigAccessMetadata& arg);
};

class LibvigAccessArgument {
public:
  enum Type {
    READ, WRITE, RESULT
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

  bool are_dependencies_sorted;

  /*
   * There should never be repeating elements inside this vector.
   *
   * I considered using an unordered_set, but it involved more work
   * than I expected. So, in order to contain my over-engineering
   * tendencies, and because this will not have many elements, I
   * decided to just use a vector.
   */
  std::vector< std::shared_ptr<const Dependency> > dependencies;

public:
  LibvigAccessArgument(const Type& _type, std::string _expr)
    : type(_type), expression(_expr), are_dependencies_sorted(false) {}

  LibvigAccessArgument(const LibvigAccessArgument& argument)
    : LibvigAccessArgument(argument.type, argument.expression) {
    for (const auto &dependency : argument.dependencies)
      dependencies.emplace_back(dependency->clone());
  }

  const std::vector< std::shared_ptr<const Dependency> > &get_dependencies() const {
    return dependencies;
  }

  void sort_dependencies() {
      if (are_dependencies_sorted) return;

      auto dependency_comparator = [](const std::shared_ptr<const Dependency>& d1,
                                      const std::shared_ptr<const Dependency>& d2) -> bool {
        if (!d1->should_ignore()) return true;
        if (!d1->is_processed()) return true;
        if (!d1->is_rss_compatible()) return true;

        if (!d2->should_ignore()) return false;
        if (!d2->is_processed()) return false;
        if (!d2->is_rss_compatible()) return false;

        const auto& processed1 = dynamic_cast<const PacketDependencyProcessed*>(d1.get());
        const auto& processed2 = dynamic_cast<const PacketDependencyProcessed*>(d2.get());

        return (*processed1) < (*processed2);
      };

      std::sort(dependencies.begin(), dependencies.end(), dependency_comparator);

      are_dependencies_sorted = true;
  }

  std::vector<R3S::R3S_pf_t> get_unique_packet_fields() const {
    std::vector<R3S::R3S_pf_t> packet_fields;

    for (const auto &dependency : dependencies) {
      if (dependency->should_ignore()) continue;
      if (!dependency->is_processed()) continue;
      if (!dependency->is_rss_compatible()) continue;

      const auto packet_dependency_processed = dynamic_cast<const PacketDependencyProcessed*>(dependency.get());
      auto packet_field = packet_dependency_processed->get_packet_field();
      auto found_it =
          std::find(packet_fields.begin(), packet_fields.end(), packet_field);
      if (found_it != packet_fields.end())
        continue;
      packet_fields.push_back(packet_field);
    }

    return packet_fields;
  }

  void add_dependency(const Dependency* dependency);

  friend std::ostream& operator<<(std::ostream& os, const LibvigAccessArgument& arg);
  friend bool operator==(const LibvigAccessArgument &lhs, const LibvigAccessArgument &rhs);

private:
  void process_packet_dependency(const PacketDependency* dependency);
};

class LibvigAccess {
public:
    enum Operation {
        READ, WRITE, NOP, INIT, CREATE, VERIFY, DESTROY
    };

private:
  unsigned int id;
  unsigned int src_device;
  std::pair<bool, unsigned int> dst_device;
  Operation operation;
  unsigned int object;

  std::vector<LibvigAccessArgument> arguments;
  std::pair<bool, LibvigAccessMetadata> metadata;

public:
  LibvigAccess(const unsigned int &_id,
               const unsigned int &_src_device,
               const std::pair<bool, unsigned int> _dst_device,
               const Operation& _operation, const unsigned int &_object)
      : id(_id), src_device(_src_device), dst_device(_dst_device),
        operation(_operation), object(_object) {
    metadata.first = false;
  }

  LibvigAccess(const LibvigAccess &access)
      : LibvigAccess(access.id, access.src_device, access.dst_device, access.operation, access.object) {
    arguments = access.arguments;
    metadata = access.metadata;
  }

  const unsigned int &get_id() const { return id; }
  const unsigned int &get_src_device() const { return src_device; }
  const unsigned int &get_dst_device() const { assert(dst_device.first); return dst_device.second; }
  const Operation &get_operation() const { return operation; }
  const unsigned int &get_object() const { return object; }
  const std::vector<LibvigAccessArgument>& get_arguments() const { return arguments; }
  const LibvigAccessMetadata& get_metadata() const { assert(metadata.first); return metadata.second; }

  const bool is_dst_device_set() const { return dst_device.first; }
  const bool is_metadata_set() const { return metadata.first; }

  void add_argument(const LibvigAccessArgument& argument) {
    arguments.emplace_back(argument);
  }

  void add_metadata(const LibvigAccessMetadata& _metadata) {
    metadata = std::make_pair(true, _metadata);
  }

  friend std::ostream& operator<<(std::ostream& os, const LibvigAccess& access);
  friend bool operator==(const LibvigAccess& lhs, const LibvigAccess& rhs);

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

      if (operation == Tokens::Operations::DESTROY) {
          return Operation::DESTROY;
      }

      Logger::error() << "Invalid operation token \"";
      Logger::error() << operation;
      Logger::error() << "\n";

      exit(1);
  }
};

} // namespace ParallelSynthesizer
