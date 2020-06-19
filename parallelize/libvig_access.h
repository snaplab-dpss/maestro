#pragma once

#include <iostream>
#include <memory>
#include <vector>

#include <r3s.h>

namespace ParallelSynthesizer {

class PacketDependency {
  
private:

    unsigned int layer;
    unsigned int protocol;
    unsigned int offset;

public:

    PacketDependency(
        const unsigned int& _layer,
        const unsigned int& _protocol,
        const unsigned int& _offset
    ) : layer(_layer), protocol(_protocol), offset(_offset) {}
    
    PacketDependency(const PacketDependency &pd)
        : PacketDependency(pd.get_layer(), pd.get_protocol(), pd.get_offset()) { }

    const unsigned int& get_layer()    const { return layer;     }
    const unsigned int& get_protocol() const { return protocol;  }
    const unsigned int& get_offset()   const { return offset;    }

    virtual bool has_valid_packet_field() const { return false; }

    friend bool operator==(const PacketDependency& lhs, const PacketDependency& rhs);
    friend bool operator<(const PacketDependency& lhs, const PacketDependency& rhs);
    
    // TODO
    void process_pf();

};

class PacketDependencyProcessed : public PacketDependency {

private:
    R3S_pf_t packet_field;
    unsigned int bytes;
    
    PacketDependencyProcessed(
        const PacketDependency& _pd,
        const R3S_pf_t& _packet_field,
        const unsigned  int& _bytes
    ) : PacketDependency(_pd) {
        packet_field = _packet_field;
        bytes = _bytes;
    }

public:
    
    PacketDependencyProcessed(
        const PacketDependencyProcessed& _pdp
    ) : PacketDependency(_pdp.get_layer(), _pdp.get_protocol(), _pdp.get_offset()) {
        packet_field = _pdp.get_packet_field();
        bytes = _pdp.get_bytes();
    }
    
    bool has_valid_packet_field() const override { return true; }
    
    const R3S_pf_t& get_packet_field() const { return packet_field; }
    const unsigned int& get_bytes() const { return bytes; }
    
    friend bool operator==(const PacketDependencyProcessed& lhs, const PacketDependencyProcessed& rhs);
    
    static std::unique_ptr<PacketDependencyProcessed> try_process(const PacketDependency& pd);

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
  std::vector<PacketDependencyProcessed> packet_dependencies;
  std::vector<PacketDependency> packet_dependencies_not_processed;

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

  const std::vector<PacketDependencyProcessed>& get_dependencies() const {
    return packet_dependencies;
  }
  
  const std::vector<PacketDependency>& get_dependencies_not_processed() const {
    return packet_dependencies_not_processed;
  }

  void add_dependency(const PacketDependency& dependency);

  friend bool operator==(const LibvigAccess& lhs, const LibvigAccess& rhs);
  
  static LibvigAccess& find(std::vector<LibvigAccess>& accesses, const unsigned int& id);
  static std::vector<PacketDependencyProcessed> zip_accesses_dependencies(const LibvigAccess& access1, const LibvigAccess& access2);
};

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
