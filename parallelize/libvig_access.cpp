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

std::unique_ptr<PacketDependencyProcessed>
PacketDependencyProcessed::try_process(const PacketDependency &pd) {
  unsigned int offset = pd.get_offset();
  unsigned int layer = pd.get_layer();
  unsigned int protocol = pd.get_protocol();

  // IPv4
  if (layer == 3 && protocol == 0x0800) {

    if (offset == 9) {
      // sprintf(dep.error_descr, "IPv4 protocolcol");
    } else if (offset >= 12 && offset <= 15) {
      return std::unique_ptr<PacketDependencyProcessed>(
          new PacketDependencyProcessed(pd, R3S::R3S_PF_IPV4_SRC, 15 - offset));
    } else if (offset >= 16 && offset <= 19) {
      return std::unique_ptr<PacketDependencyProcessed>(
          new PacketDependencyProcessed(pd, R3S::R3S_PF_IPV4_DST, 19 - offset));
    } else if (offset >= 20) {
      // sprintf(dep.error_descr, "IPv4 options");
    } else {
      // sprintf(dep.error_descr, "Unknown IPv4 field at byte %u\n",
      // dep.offset);
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
      return std::unique_ptr<PacketDependencyProcessed>(
          new PacketDependencyProcessed(pd, R3S::R3S_PF_TCP_SRC, offset));
    } else if (offset >= 2 && offset <= 3) {
      return std::unique_ptr<PacketDependencyProcessed>(
          new PacketDependencyProcessed(pd, R3S::R3S_PF_TCP_DST, offset - 2));
    } else {
      // sprintf(dep.error_descr, "Unknown TCP field at byte %u\n", dep.offset);
    }
  }

  // UDP
  else if (layer == 4 && protocol == 0x11) {
    if (offset <= 1) {
      return std::unique_ptr<PacketDependencyProcessed>(
          new PacketDependencyProcessed(pd, R3S::R3S_PF_UDP_SRC, offset));
    } else if (offset >= 2 && offset <= 3) {
      return std::unique_ptr<PacketDependencyProcessed>(
          new PacketDependencyProcessed(pd, R3S::R3S_PF_UDP_DST, offset - 2));
    } else {
      // sprintf(dep.error_descr, "Unknown UDP field at byte %u\n", dep.offset);
    }
  }

  return std::unique_ptr<PacketDependencyProcessed>();
}

void LibvigAccess::add_dependency(const PacketDependency &dependency) {
  auto it = std::find(packet_dependencies.begin(), packet_dependencies.end(),
                      dependency);

  if (it != packet_dependencies.end())
    return;

  auto processed = PacketDependencyProcessed::try_process(dependency);
  if (processed) {
    packet_dependencies.push_back(*processed);
    return;
  }

  packet_dependencies_not_processed.push_back(dependency);
}

bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs) {
  return lhs.get_device() == rhs.get_device() &&
         lhs.get_object() == rhs.get_object() &&
         lhs.get_dependencies() == rhs.get_dependencies() &&
         lhs.get_dependencies_not_processed() == rhs.get_dependencies_not_processed();
    
}

LibvigAccess &LibvigAccess::find(std::vector<LibvigAccess> &accesses,
                                 const unsigned int &id) {
  for (auto &a : accesses)
    if (a.get_id() == id)
      return a;
  // throw exception

  Logger::error() << "LibvigAccess not found (id " << id << ")"
            << "\n";
  exit(1);
}

std::vector<PacketDependencyProcessed>
LibvigAccess::zip_accesses_dependencies(const LibvigAccess &access1,
                                        const LibvigAccess &access2) {
  std::vector<PacketDependencyProcessed> zipped;

  const std::vector<PacketDependencyProcessed> &access1_dependencies =
      access1.get_dependencies();

  const std::vector<PacketDependencyProcessed> &access2_dependencies =
      access2.get_dependencies();

  zipped.insert(zipped.end(), access1_dependencies.begin(), access1_dependencies.end());
  zipped.insert(zipped.end(), access2_dependencies.begin(), access2_dependencies.end());
  
  std::sort(zipped.begin(), zipped.end());

  return zipped;
}
}
