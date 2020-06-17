#pragma once

#include <r3s.h>

#include <memory>
#include <vector>

namespace ParallelSynthesizer {
namespace ConstraintsGenerator {

class PacketDependency {
  
private:

  unsigned int layer;
  unsigned int protocol;
  unsigned int offset;
  unsigned int bytes;

  std::unique_ptr<R3S_pf_t> pf;

private:

  void set_pf(const R3S_pf_t& _pf) {
    pf = std::unique_ptr<R3S_pf_t> (new R3S_pf_t(_pf));
  }

public:

  PacketDependency(const PacketDependency &pd)
    : PacketDependency(pd.get_layer(), pd.get_protocol(), pd.get_offset()) { }

  PacketDependency(
    const unsigned int& _layer,
    const unsigned int& _protocol,
    const unsigned int& _offset
  ) : layer(_layer), protocol(_protocol), offset(_offset) {
    
    // IPv4
    if (layer == 3 && protocol == 0x0800) {

      if (offset == 9) {
        //sprintf(dep.error_descr, "IPv4 protocolcol");
      }
      
      else if (offset >= 12 && offset <= 15) {
        set_pf(R3S_PF_IPV4_SRC);
        bytes = 15 - offset;
      }
      
      else if (offset >= 16 && offset <= 19) {
        set_pf(R3S_PF_IPV4_DST);
        bytes = 19 - offset;
      }
      
      else if (offset >= 20) {
        // sprintf(dep.error_descr, "IPv4 options");
      }
      
      else {
        // sprintf(dep.error_descr, "Unknown IPv4 field at byte %u\n", dep.offset);
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
        set_pf(R3S_PF_TCP_SRC);
        bytes = offset;
      }
      
      else if (offset >= 2 && offset <= 3) {
        set_pf(R3S_PF_TCP_DST);
        bytes = offset - 2;
      }
      
      else {
        // sprintf(dep.error_descr, "Unknown TCP field at byte %u\n", dep.offset);
      }
    }

    // UDP
    else if (layer == 4 && protocol == 0x11) {
      if (offset <= 1) {
        set_pf(R3S_PF_UDP_SRC);
        bytes = offset;
      }
      
      else if (offset >= 2 && offset <= 3) {
        set_pf(R3S_PF_UDP_DST);
        bytes = offset - 2;
      }
      
      else {
        // sprintf(dep.error_descr, "Unknown UDP field at byte %u\n", dep.offset);
      }
    }
  }

  const unsigned int& get_layer()    const { return layer;     }
  const unsigned int& get_protocol() const { return protocol;  }
  const unsigned int& get_offset()   const { return offset;    }
  const unsigned int& get_bytes()    const { return bytes;     }

  friend bool operator==(const PacketDependency& lhs, const PacketDependency& rhs);

  // TODO
  void process_pf();

};

class LibvigAccess {

private:

  unsigned int id;
  unsigned int device;
  unsigned int object;

  /*
   * There should never be repeating elements inside this vector.
   * 
   * I considered using an unordered_set, but it involved more work
   * than I expected. So, in order to contain my over-engineering
   * tendencies, and because this will not have many elements, I
   * decided to just use a vector.
   */
  std::vector<PacketDependency> packet_dependencies;

public:

  LibvigAccess(
    const unsigned int& _id,
    const unsigned int& _device,
    const unsigned int& _object
  ) : id(_id), device(_device), object(_object) {}

  LibvigAccess(const LibvigAccess& access)
    : LibvigAccess(
      access.get_id(),
      access.get_device(),
      access.get_object()
  ) {
    for (const auto& dependency : access.get_dependencies())
      packet_dependencies.emplace_back(dependency);  
  }

  const unsigned int& get_id()     const { return id;     }
  const unsigned int& get_device() const { return device; }
  const unsigned int& get_object() const { return object; }

  const std::vector<PacketDependency>& get_dependencies() const {
    return packet_dependencies;
  }

  void add_dependency(const PacketDependency& dependency);

  friend bool operator==(const LibvigAccess& lhs, const LibvigAccess& rhs);
};

}
}

/*
typedef struct {
  unsigned offset;
  unsigned bytes;    // big endian
  R3S_pf_t pf;
  bool     pf_is_set;
  char     error_descr[50];
} dep_t;

typedef struct {
  dep_t  *deps;
  size_t sz;
} deps_t;

bool dep_eq(dep_t d1, dep_t d2);
bool dep_in_array(deps_t deps, dep_t dep);
void deps_init(deps_t *deps);
void deps_destroy(deps_t *deps);
void deps_append_unique(deps_t *deps, dep_t dep);
deps_t deps_merge(deps_t deps1, deps_t deps2);

typedef struct {
  unsigned id;
  unsigned device;
  unsigned obj;
  unsigned layer;
  unsigned protocol;
  deps_t deps;
} libvig_access_t;

typedef struct {
  libvig_access_t *accesses;
  size_t sz;
} libvig_accesses_t;

bool libvig_access_eq(libvig_access_t l1, libvig_access_t l2);
bool libvig_access_in_array(libvig_access_t access, libvig_accesses_t accesses);

void libvig_accesses_init(libvig_accesses_t *accesses);
void libvig_accesses_destroy(libvig_accesses_t *accesses);
libvig_access_t* libvig_access_get_from_id(libvig_accesses_t *accesses, unsigned id);
void libvig_accesses_append_unique(libvig_access_t access,
                                   libvig_accesses_t *accesses);

dep_t dep_from_offset(unsigned offset, libvig_access_t access);
*/
