#include "logger.h"
#include "libvig_access.h"

#include <algorithm>
#include <iostream>

namespace ParallelSynthesizer {

bool operator==(const PacketDependency &lhs, const PacketDependency &rhs) {
  return lhs.layer == rhs.layer && lhs.offset == rhs.offset &&
         lhs.protocol == rhs.protocol;
}

bool operator<(const PacketDependency &lhs, const PacketDependency &rhs) {
  if (lhs.get_layer() < rhs.get_layer())
    return true;
  if (lhs.get_layer() > rhs.get_layer())
    return false;

  if (lhs.get_offset() < rhs.get_offset())
    return true;

  return false;
}

bool operator==(const PacketDependencyProcessed &lhs,
                const PacketDependencyProcessed &rhs) {
  return lhs.bytes == rhs.bytes && lhs.get_layer() == rhs.get_layer() &&
         lhs.get_offset() == rhs.get_offset() &&
         lhs.get_protocol() == rhs.get_protocol();
}

bool operator==(const PacketDependencyIncompatible &lhs, const PacketDependencyIncompatible &rhs) {
  return lhs.get_description() == rhs.get_description();
}

void LibvigAccess::add_dependency(const PacketDependencyProcessed &dependency) {
  packet_dependencies.push_back(dependency);
}

void LibvigAccess::add_dependency(
    const PacketDependencyIncompatible &dependency) {
  packet_dependencies_incompatible.push_back(dependency);
}

void LibvigAccess::add_dependency(const PacketDependency &dependency) {
  auto it = std::find(packet_dependencies.begin(), packet_dependencies.end(),
                      dependency);

  if (it != packet_dependencies.end())
    return;

  unsigned int offset = dependency.get_offset();
  unsigned int layer = dependency.get_layer();
  unsigned int protocol = dependency.get_protocol();

  // IPv4
  if (layer == 3 && protocol == 0x0800) {

    if (offset == 9) {
      // The call path generator and analyzer generates all possible
      // values for protocol.
      // It is complete. Therefore, this field can be ignored. If one
      // incompatible protocol value is used, then it will be caught
      // later on the incompatible field.
      add_dependency(PacketDependencyProcessed(dependency, 0));
      return;
    } else if (offset >= 12 && offset <= 15) {
      add_dependency(PacketDependencyProcessed(dependency, R3S::R3S_PF_IPV4_SRC, 15 - offset));
      return;
    } else if (offset >= 16 && offset <= 19) {
      add_dependency(PacketDependencyProcessed(dependency, R3S::R3S_PF_IPV4_DST, 19 - offset));
      return;
    } else if (offset >= 20) {
      add_dependency(PacketDependencyIncompatible(dependency, "IPv4 options"));
      return;
    } else {
      add_dependency(PacketDependencyIncompatible(dependency, "Unknown IPv4 field"));
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
      add_dependency(PacketDependencyProcessed(dependency, R3S::R3S_PF_TCP_SRC, offset));
      return;
    } else if (offset >= 2 && offset <= 3) {
      add_dependency(PacketDependencyProcessed(dependency, R3S::R3S_PF_TCP_DST, offset - 2));
      return;
    } else {
      add_dependency(PacketDependencyIncompatible(dependency, "Unknown TCP field"));
      return;
    }
  }

  // UDP
  else if (layer == 4 && protocol == 0x11) {
    if (offset <= 1) {
      add_dependency(PacketDependencyProcessed(dependency, R3S::R3S_PF_UDP_SRC, offset));
      return;
    } else if (offset >= 2 && offset <= 3) {
      add_dependency(PacketDependencyProcessed(dependency, R3S::R3S_PF_UDP_DST, offset - 2));
      return;
    } else {
      add_dependency(PacketDependencyIncompatible(dependency, "Unknown UDP field"));
      return;
    }
  }

  else {
    std::stringstream s;
    s << "Unknown (layer: ";
    s << dependency.get_layer();
    s << ", protocol: ";
    s << dependency.get_protocol();
    s << ", offset: ";
    s << dependency.get_offset();
    s << ")";

    add_dependency(PacketDependencyIncompatible(dependency, s.str()));
  }
}

bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs) {
  return lhs.get_id() == rhs.get_id();
}

LibvigAccess &LibvigAccess::find_by_id(std::vector<LibvigAccess> &accesses,
                                 const unsigned int &id) {
  for (auto &a : accesses)
    if (a.get_id() == id)
      return a;

  Logger::error() << "LibvigAccess not found (id " << id << ")"
                  << "\n";
  exit(1);
}

bool LibvigAccess::content_equal(const LibvigAccess &access1,
                                 const LibvigAccess &access2) {
  return access1.get_device() == access2.get_device() &&
         access1.get_object() == access2.get_object() &&
         access1.get_dependencies() == access2.get_dependencies() &&
         access1.get_dependencies_incompatible() == access2.get_dependencies_incompatible();
}

} // namespace ParallelSynthesizer
