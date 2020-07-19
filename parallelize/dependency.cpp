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
  if (lhs.get_layer() < rhs.get_layer())
    return true;

  if (lhs.get_layer() > rhs.get_layer())
    return false;

  if (lhs.get_offset() < rhs.get_offset())
    return true;

  return false;
}

std::ostream& operator<<(std::ostream& os, const Dependency& dependency) {
    dependency.print(os);

    if (dependency.ignore) {
        os << " [ignored]";
    }

    if (!dependency.packet_related){
        os << " [non packet related]";
    }

    return os;
}

bool operator==(const PacketDependencyProcessed &lhs,
                const PacketDependencyProcessed &rhs) {
  return lhs.bytes == rhs.bytes &&
         lhs.get_layer() == rhs.get_layer() &&
         lhs.get_offset() == rhs.get_offset() &&
         lhs.get_protocol() == rhs.get_protocol();
}

bool operator==(const PacketDependencyIncompatible &lhs, const PacketDependencyIncompatible &rhs) {
  return lhs.get_description() == rhs.get_description();
}

} // namespace ParallelSynthesizer
