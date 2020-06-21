#pragma once

#include <iostream>
#include <memory>
#include <vector>
#include <algorithm>

namespace R3S {
#include <r3s.h>
}

namespace ParallelSynthesizer {

class PacketDependency {

private:
  unsigned int layer;
  unsigned int protocol;
  unsigned int offset;

public:
  PacketDependency(const unsigned int &_layer, const unsigned int &_protocol,
                   const unsigned int &_offset)
      : layer(_layer), protocol(_protocol), offset(_offset) {}

  PacketDependency(const PacketDependency &pd)
      : PacketDependency(pd.get_layer(), pd.get_protocol(), pd.get_offset()) {}

  const unsigned int &get_layer() const { return layer; }
  const unsigned int &get_protocol() const { return protocol; }
  const unsigned int &get_offset() const { return offset; }

  virtual bool has_valid_packet_field() const { return false; }

  friend bool operator==(const PacketDependency &lhs,
                         const PacketDependency &rhs);
  friend bool operator<(const PacketDependency &lhs,
                        const PacketDependency &rhs);
};

class PacketDependencyIncompatible : public PacketDependency {

private:
  std::string description;

public:
  PacketDependencyIncompatible(const PacketDependency &_pd,
                               const std::string &_description)
      : PacketDependency(_pd) {
    description = _description;
  }

  PacketDependencyIncompatible(const PacketDependencyIncompatible &_pdi)
      : PacketDependency(_pdi.get_layer(), _pdi.get_protocol(),
                         _pdi.get_offset()) {
    description = _pdi.get_description();
  }

  bool has_valid_packet_field() const override { return false; }
  const std::string &get_description() const { return description; }

  friend bool operator==(const PacketDependencyIncompatible &lhs,
                         const PacketDependencyIncompatible &rhs);
};

class PacketDependencyProcessed : public PacketDependency {

private:
  R3S::R3S_pf_t packet_field;
  unsigned int bytes;

public:
  PacketDependencyProcessed(const PacketDependency &_pd,
                            const R3S::R3S_pf_t &_packet_field,
                            const unsigned int &_bytes)
      : PacketDependency(_pd) {
    packet_field = _packet_field;
    bytes = _bytes;
  }

  PacketDependencyProcessed(const PacketDependencyProcessed &_pdp)
      : PacketDependency(_pdp.get_layer(), _pdp.get_protocol(),
                         _pdp.get_offset()) {
    packet_field = _pdp.get_packet_field();
    bytes = _pdp.get_bytes();
  }

  bool has_valid_packet_field() const override { return true; }

  const R3S::R3S_pf_t &get_packet_field() const { return packet_field; }
  const unsigned int &get_bytes() const { return bytes; }

  friend bool operator==(const PacketDependencyProcessed &lhs,
                         const PacketDependencyProcessed &rhs);
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
  std::vector<PacketDependencyIncompatible> packet_dependencies_incompatible;

public:
  LibvigAccess(const unsigned int &_id, const unsigned int &_device,
               const unsigned int &_object)
      : id(_id), device(_device), object(_object) {}

  LibvigAccess(const LibvigAccess &access)
      : LibvigAccess(access.get_id(), access.get_device(),
                     access.get_object()) {
    for (const auto &dependency : access.get_dependencies())
      packet_dependencies.emplace_back(dependency);

    for (const auto &dependency : access.get_dependencies_incompatible())
      packet_dependencies_incompatible.emplace_back(dependency);
  }

  const unsigned int &get_id() const { return id; }
  const unsigned int &get_device() const { return device; }
  const unsigned int &get_object() const { return object; }

  const std::vector<PacketDependencyProcessed> &get_dependencies() const {
    return packet_dependencies;
  }

  const std::vector<PacketDependencyIncompatible> &
  get_dependencies_incompatible() const {
    return packet_dependencies_incompatible;
  }

  std::vector<R3S::R3S_pf_t> get_unique_packet_fields() const {
    std::vector<R3S::R3S_pf_t> packet_fields;

    for (const auto &dependency : packet_dependencies) {
      auto packet_field = dependency.get_packet_field();
      auto found_it =
          std::find(packet_fields.begin(), packet_fields.end(), packet_field);
      if (found_it != packet_fields.end())
        continue;
      packet_fields.push_back(packet_field);
    }

    return packet_fields;
  }

  void add_dependency(const PacketDependency &dependency);
  void add_dependency(const PacketDependencyProcessed &dependency);
  void add_dependency(const PacketDependencyIncompatible &dependency);

  friend bool operator==(const LibvigAccess &lhs, const LibvigAccess &rhs);

  static LibvigAccess &find_by_id(std::vector<LibvigAccess> &accesses,
                                  const unsigned int &id);
  static bool content_equal(const LibvigAccess &access1,
                            const LibvigAccess &access2);
  static std::vector<PacketDependencyProcessed>
  zip_accesses_dependencies(const LibvigAccess &access1,
                            const LibvigAccess &access2);
};

} // namespace ParallelSynthesizer
