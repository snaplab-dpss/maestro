#include "logger.h"
#include "dependency.h"

#include <algorithm>
#include <iostream>

namespace ParallelSynthesizer {

bool operator==(const PacketDependency &lhs, const PacketDependency &rhs) {
  return lhs.layer == rhs.layer && lhs.offset == rhs.offset &&
         lhs.protocol == rhs.protocol;
}

bool operator<(const PacketDependency &lhs, const PacketDependency &rhs) {
  if (lhs.get_layer() < rhs.get_layer()) return true;

  if (lhs.get_layer() > rhs.get_layer()) return false;

  if (lhs.get_offset() < rhs.get_offset()) return true;

  return false;
}

std::ostream &operator<<(std::ostream &os, const Dependency &dependency) {
  dependency.print(os);

  if (dependency.ignore) {
    os << " [ignored]";
  }

  if (!dependency.packet_related) {
    os << " [non packet related]";
  }

  return os;
}

bool operator==(const PacketDependencyProcessed &lhs,
                const PacketDependencyProcessed &rhs) {
  return lhs.bytes == rhs.bytes && lhs.get_layer() == rhs.get_layer() &&
         lhs.get_offset() == rhs.get_offset() &&
         lhs.get_protocol() == rhs.get_protocol();
}

bool operator==(const PacketDependencyIncompatible &lhs,
                const PacketDependencyIncompatible &rhs) {
  return lhs.get_description() == rhs.get_description();
}

void DependencyManager::add_dependency(const Dependency *dependency) {
  assert(dependency && "invalid dependency");

  if (!dependency->is_processed() && dependency->is_packet_related()) {
    const auto packet_dependency =
        dynamic_cast<const PacketDependency *>(dependency);
    assert(packet_dependency);
    process_packet_dependency(packet_dependency);
  } else if (!dependency->is_processed() && !dependency->is_packet_related()) {
    // TODO:
    assert(false && "not implemented");
  } else {
    dependencies.emplace_back(dependency->clone());
    are_dependencies_sorted = false;
  }
}

bool operator==(const DependencyManager &lhs, const DependencyManager &rhs) {
  return lhs.get() == rhs.get();
}

std::ostream &operator<<(std::ostream &os, const DependencyManager &manager) {
  if (manager.dependencies.size()) {
    os << "  dependencies";
    os << " (" << manager.dependencies.size() << "):";
    for (const auto &dep : manager.dependencies) {
      os << "\n";
      os << "    ";
      os << *dep.get();
    }
    os << "\n";
  }

  return os;
}

void DependencyManager::process_packet_dependency(
    const PacketDependency *dependency_ptr) {
  assert(dependency_ptr && "invalid dependency");

  const auto dependency = *dependency_ptr;

  auto it =
      std::find_if(dependencies.begin(), dependencies.end(),
                   [&](const std::shared_ptr<Dependency> & _dependency)->bool {
        if (!_dependency->is_processed()) return false;
        if (!_dependency->is_packet_related()) return false;

        const auto _packet_dependency =
            dynamic_cast<const PacketDependency *>(_dependency.get());
        assert(_packet_dependency);

        return (*_packet_dependency) == dependency;
      });

  if (it != dependencies.end()) return;

  auto offset = dependency.get_offset();
  auto layer = dependency.get_layer();
  auto protocol = dependency.get_protocol();

  if (layer == 2) {
    // TODO: ethertype

    auto processed = PacketDependencyIncompatible(dependency, "Ethernet field");
    add_dependency(processed.clone().get());
    return;
  }

  // IPv4
  if (layer == 3 && protocol == 0x0800) {

    if (offset == 9) {
      // The call path generator and analyzer generates all possible
      // values for protocol.
      // It is complete. Therefore, this field can be ignored. If one
      // incompatible protocol value is used, then it will be caught
      // later on the incompatible field.
      auto processed =
          PacketDependencyIncompatible(dependency, "IPv4 protocol", true);
      add_dependency(processed.clone().get());
      return;
    } else if (offset >= 12 && offset <= 15) {
      auto processed = PacketDependencyProcessed(
          dependency, R3S::R3S_PF_IPV4_SRC, 15 - offset);
      add_dependency(processed.clone().get());
      return;
    } else if (offset >= 16 && offset <= 19) {
      auto processed = PacketDependencyProcessed(
          dependency, R3S::R3S_PF_IPV4_DST, 19 - offset);
      add_dependency(processed.clone().get());
      return;
    } else if (offset >= 20) {
      auto processed = PacketDependencyIncompatible(dependency, "IPv4 options");
      add_dependency(processed.clone().get());
      return;
    } else {
      auto processed =
          PacketDependencyIncompatible(dependency, "Unknown IPv4 field");
      add_dependency(processed.clone().get());
      return;
    }
  }

  // IPv6
  else if (layer == 3 && protocol == 0x86DD) {

  }

  // VLAN
  else if (layer == 3 && protocol == 0x8100) {

  }

  // TCP
  else if (layer == 4 && protocol == 0x06) {
    if (offset <= 1) {
      auto processed =
          PacketDependencyProcessed(dependency, R3S::R3S_PF_TCP_SRC, offset);
      add_dependency(processed.clone().get());
      return;
    } else if (offset >= 2 && offset <= 3) {
      auto processed = PacketDependencyProcessed(
          dependency, R3S::R3S_PF_TCP_DST, offset - 2);
      add_dependency(processed.clone().get());
      return;
    } else {
      auto processed =
          PacketDependencyIncompatible(dependency, "Unknown TCP field");
      add_dependency(processed.clone().get());
      return;
    }
  }

  // UDP
  else if (layer == 4 && protocol == 0x11) {
    if (offset <= 1) {
      auto processed =
          PacketDependencyProcessed(dependency, R3S::R3S_PF_UDP_SRC, offset);
      add_dependency(processed.clone().get());
      return;
    } else if (offset >= 2 && offset <= 3) {
      auto processed = PacketDependencyProcessed(
          dependency, R3S::R3S_PF_UDP_DST, offset - 2);
      add_dependency(processed.clone().get());
      return;
    } else {
      auto processed =
          PacketDependencyIncompatible(dependency, "Unknown UDP field");
      add_dependency(processed.clone().get());
      return;
    }
  } else {
    auto processed = PacketDependencyIncompatible(dependency, "Unknown");
    add_dependency(processed.clone().get());
    return;
  }
}

}  // namespace ParallelSynthesizer
