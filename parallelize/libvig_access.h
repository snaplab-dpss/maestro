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

class LibvigAccess {
public:
    enum Operation {
        READ, WRITE, NOP, INIT
    };

private:
  unsigned int id;
  unsigned int device;
  unsigned int object;
  Operation operation;

  bool are_dependencies_sorted;

  /*
   * There should never be repeating elements inside this vector.
   *
   * I considered using an unordered_set, but it involved more work
   * than I expected. So, in order to contain my over-engineering
   * tendencies, and because this will not have many elements, I
   * decided to just use a vector.
   */
  std::vector< std::unique_ptr<const Dependency> > dependencies;

public:
  LibvigAccess(const unsigned int &_id, const unsigned int &_device,
               const unsigned int &_object, const Operation& _operation)
      : id(_id), device(_device), object(_object),
        operation(_operation), are_dependencies_sorted(false) {}

  LibvigAccess(const LibvigAccess &access)
      : LibvigAccess(access.get_id(), access.get_device(),
                     access.get_object(), access.get_operation()) {
    for (const auto &dependency : access.get_dependencies())
      dependencies.emplace_back(dependency->clone());
  }

  const unsigned int &get_id() const { return id; }
  const unsigned int &get_device() const { return device; }
  const unsigned int &get_object() const { return object; }
  const Operation &get_operation() const { return operation; }

  const std::vector< std::unique_ptr<const Dependency> > &get_dependencies() const {
    return dependencies;
  }

  void sort_dependencies() {
      if (are_dependencies_sorted) return;

      auto dependency_comparator = [](const std::unique_ptr<const Dependency>& d1,
                                      const std::unique_ptr<const Dependency>& d2) -> bool {
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

  friend bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs);
  friend std::ostream& operator<<(std::ostream& os, const LibvigAccess& access);

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

      Logger::error() << "Invalid operation token \"";
      Logger::error() << operation;
      Logger::error() << "\n";

      exit(1);
  }

private:
  void process_packet_dependency(const PacketDependency* dependency);
};

} // namespace ParallelSynthesizer
