#include "logger.h"
#include "dependency.h"
#include "libvig_access.h"

#include <algorithm>
#include <iostream>

namespace ParallelSynthesizer {

void LibvigAccessArgument::add_dependency(const Dependency* dependency) {
    assert(dependency && "invalid dependency");

    if (!dependency->is_processed() && dependency->is_packet_related()) {
      const auto packet_dependency = dynamic_cast<const PacketDependency*>(dependency);
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

void LibvigAccessArgument::process_packet_dependency(const PacketDependency* dependency_ptr) {
  assert(dependency_ptr && "invalid dependency");

  const auto dependency = *dependency_ptr;

  auto it = std::find_if(
    dependencies.begin(),
    dependencies.end(),
    [&](const std::shared_ptr<const Dependency>& _dependency) -> bool {
      if (!_dependency->is_processed()) return false;
      if (!_dependency->is_packet_related()) return false;

      const auto _packet_dependency = dynamic_cast<const PacketDependency*>(_dependency.get());
      assert(_packet_dependency);

      return (*_packet_dependency) == dependency;
    }
  );

  if (it != dependencies.end())
    return;

  auto offset = dependency.get_offset();
  auto layer = dependency.get_layer();
  auto protocol = dependency.get_protocol();

  if (layer == 2) {
      // TODO: ethertype

      auto processed = PacketDependencyIncompatible(dependency, "Ethernet field");
      add_dependency(processed.get_unique().get());
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
      auto processed = PacketDependencyIncompatible(dependency, "IPv4 protocol", true);
      add_dependency(processed.get_unique().get());
      return;
    } else if (offset >= 12 && offset <= 15) {
      auto processed = PacketDependencyProcessed(dependency, R3S::R3S_PF_IPV4_SRC, 15 - offset);
      add_dependency(processed.get_unique().get());
      return;
    } else if (offset >= 16 && offset <= 19) {
      auto processed = PacketDependencyProcessed(dependency, R3S::R3S_PF_IPV4_DST, 19 - offset);
      add_dependency(processed.get_unique().get());
      return;
    } else if (offset >= 20) {
      auto processed = PacketDependencyIncompatible(dependency, "IPv4 options");
      add_dependency(processed.get_unique().get());
      return;
    } else {
      auto processed = PacketDependencyIncompatible(dependency, "Unknown IPv4 field");
      add_dependency(processed.get_unique().get());
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
      auto processed = PacketDependencyProcessed(dependency, R3S::R3S_PF_TCP_SRC, offset);
      add_dependency(processed.get_unique().get());
      return;
    } else if (offset >= 2 && offset <= 3) {
      auto processed = PacketDependencyProcessed(dependency, R3S::R3S_PF_TCP_DST, offset - 2);
      add_dependency(processed.get_unique().get());
      return;
    } else {
      auto processed = PacketDependencyIncompatible(dependency, "Unknown TCP field");
      add_dependency(processed.get_unique().get());
      return;
    }
  }

  // UDP
  else if (layer == 4 && protocol == 0x11) {
    if (offset <= 1) {
      auto processed = PacketDependencyProcessed(dependency, R3S::R3S_PF_UDP_SRC, offset);
      add_dependency(processed.get_unique().get());
      return;
    } else if (offset >= 2 && offset <= 3) {
      auto processed = PacketDependencyProcessed(dependency, R3S::R3S_PF_UDP_DST, offset - 2);
      add_dependency(processed.get_unique().get());
      return;
    } else {
      auto processed = PacketDependencyIncompatible(dependency, "Unknown UDP field");
      add_dependency(processed.get_unique().get());
      return;
    }
  }

  else {
    auto processed = PacketDependencyIncompatible(dependency, "Unknown");
    add_dependency(processed.get_unique().get());
    return;
  }
}

bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs) {
  return lhs.get_id() == rhs.get_id();
}

std::ostream& operator<<(std::ostream& os, const LibvigAccessMetadata& arg) {
  os << "  interface  ";
  os << arg.interface;
  os << "\n";

  os << "  file       ";
  os << arg.file;
  os << "\n";

  return os;
}

std::ostream& operator<<(std::ostream& os, const LibvigAccessArgument& arg) {
  os << "  type       ";
  switch(arg.type) {
  case LibvigAccessArgument::Type::READ:
    os << "read";
    break;
  case LibvigAccessArgument::Type::WRITE:
    os << "write";
    break;
  case LibvigAccessArgument::Type::RESULT:
    os << "result";
    break;
  }
  os << "\n";

  os << "  expression ";
  os << arg.expression;
  os << "\n";

  if (arg.dependencies.size()) {
    os << "  dependencies";
    os << " (" << arg.dependencies.size() << "):";
    for (const auto& dep : arg.dependencies) {
          os << "\n";
          os << "    ";
          os << *dep.get();
    }
    os << "\n";
  }

  return os;
}

std::ostream& operator<<(std::ostream& os, const LibvigAccess& access) {
  os << "================ ACCESS ================" << "\n";
  os << "id         ";
  os << access.id;
  os << "\n";

  os << "src device ";
  os << access.src_device;
  os << "\n";

  if (access.dst_device.first) {
    os << "dst device ";
    os << access.dst_device.second;
    os << "\n";
  }

  os << "operation  ";
  switch (access.operation) {
    case LibvigAccess::INIT:
      os << "init";
      break;
    case LibvigAccess::READ:
      os << "read";
      break;
    case LibvigAccess::WRITE:
      os << "write";
      break;
    case LibvigAccess::CREATE:
      os << "create";
      break;
    case LibvigAccess::VERIFY:
      os << "verify";
      break;
    case LibvigAccess::DESTROY:
      os << "delete";
      break;
    case LibvigAccess::NOP:
      os << "nop";
      break;
  }
  os << "\n";

  os << "object     ";
  os << access.object;
  os << "\n";

  if (access.arguments.size()) {
    os << "arguments:";
    for (const auto& arg : access.arguments) {
      os << "\n";
      os << arg;
    }
  }

  if (access.metadata.first) {
    os << "metadata:";
    os << "\n";
    os << access.metadata.second;
  }

  os << "========================================" << "\n";

  return os;
}

bool operator==(const LibvigAccessArgument &lhs, const LibvigAccessArgument &rhs) {
  return lhs.type == rhs.type &&
      lhs.expression == rhs.expression &&
      lhs.get_dependencies() == rhs.get_dependencies();
}

bool LibvigAccess::content_equal(const LibvigAccess &access1,
                                 const LibvigAccess &access2) {
  if (access1.get_src_device() != access2.get_src_device())
    return false;

  if (access1.is_dst_device_set() != access2.is_dst_device_set())
    return false;

  if (access1.is_dst_device_set() && (access1.get_dst_device() != access2.get_dst_device()))
    return false;

  if (access1.get_object() != access2.get_object())
    return false;

  if (access1.get_operation() != access2.get_operation())
    return false;

  if (access1.get_arguments() != access2.get_arguments())
    return false;

  return true;
}

} // namespace ParallelSynthesizer
