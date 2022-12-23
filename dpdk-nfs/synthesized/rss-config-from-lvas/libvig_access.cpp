#include "logger.h"
#include "dependency.h"
#include "libvig_access.h"

#include <algorithm>
#include <iostream>

namespace ParallelSynthesizer {

const LibvigAccessArgument &LibvigAccess::get_argument(
    const LibvigAccessArgument::Type &type) const {
  auto is_right_arg_type = [&](const LibvigAccessArgument & arg)->bool {
    return arg.get_type() == type;
  };

  auto found_it =
      std::find_if(arguments.begin(), arguments.end(), is_right_arg_type);

  if (found_it != arguments.end()) return *found_it;

  assert(false && "Argument type not in this LibvigAccess");
}

bool LibvigAccess::has_argument(const LibvigAccessArgument::Type &type) const {
  auto is_right_arg_type = [&](const LibvigAccessArgument & arg)->bool {
    return arg.get_type() == type;
  };

  auto found_it =
      std::find_if(arguments.begin(), arguments.end(), is_right_arg_type);

  return found_it != arguments.end();
}

bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs) {
  return lhs.get_id() == rhs.get_id();
}

std::ostream &operator<<(std::ostream &os, const LibvigAccessMetadata &arg) {
  os << "  interface  ";
  os << arg.interface;
  os << "\n";

  os << "  file       ";
  os << arg.file;
  os << "\n";

  return os;
}

std::ostream &operator<<(std::ostream &os, const LibvigAccessArgument &arg) {
  os << "  type       ";
  switch (arg.type) {
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

  os << arg.dependencies;

  return os;
}

std::ostream &operator<<(std::ostream &os, const LibvigAccess &access) {
  os << "================ ACCESS ================"
     << "\n";
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

  if (access.success.first) {
    os << "successs   ";
    os << access.success.second;
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
    case LibvigAccess::UPDATE:
      os << "update";
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
    for (const auto &arg : access.arguments) {
      os << "\n";
      os << arg;
    }
  }

  if (access.metadata.first) {
    os << "metadata:";
    os << "\n";
    os << access.metadata.second;
  }

  os << "========================================"
     << "\n";

  return os;
}

bool operator==(const LibvigAccessArgument &lhs,
                const LibvigAccessArgument &rhs) {
  return lhs.type == rhs.type && lhs.expression == rhs.expression &&
         lhs.get_dependencies() == rhs.get_dependencies();
}

bool LibvigAccess::content_equal(const LibvigAccess &access1,
                                 const LibvigAccess &access2) {
  if (access1.get_src_device() != access2.get_src_device()) return false;

  if (access1.is_dst_device_set() != access2.is_dst_device_set()) return false;

  if (access1.is_dst_device_set() &&
      (access1.get_dst_device() != access2.get_dst_device()))
    return false;

  if (access1.get_object() != access2.get_object()) return false;

  if (access1.get_operation() != access2.get_operation()) return false;

  if (access1.get_arguments() != access2.get_arguments()) return false;

  return true;
}

}  // namespace ParallelSynthesizer
