#pragma once

#include <assert.h>
#include <memory>
#include <iostream>
#include <vector>
#include <algorithm>

namespace R3S {
#include <r3s.h>
}

#include "logger.h"

namespace ParallelSynthesizer {

class Dependency {
protected:
  bool ignore;
  bool rss_compatible;
  bool processed;
  bool packet_related;

  Dependency(bool _ignore, bool _rss_compatible, bool _processed,
             bool _packet_related)
      : ignore(_ignore), rss_compatible(_rss_compatible), processed(_processed),
        packet_related(_packet_related) {}

  virtual std::ostream &print(std::ostream &os) const = 0;

public:
  bool should_ignore() const { return ignore; }
  bool is_rss_compatible() const { return rss_compatible; }
  bool is_processed() const { return processed; }
  bool is_packet_related() const { return packet_related; }

  virtual std::shared_ptr<Dependency> clone() const = 0;

  friend std::ostream &operator<<(std::ostream &os,
                                  const Dependency &dependency);

  virtual ~Dependency() {}
};

class PacketDependency : public Dependency {

protected:
  unsigned int layer;
  unsigned int offset;
  std::pair<bool, unsigned int> protocol;

public:
  PacketDependency(const unsigned int &_layer, const unsigned int &_offset,
                   const std::pair<bool, unsigned int> &_protocol)
      : Dependency(false, false, false, true), layer(_layer), offset(_offset),
        protocol(_protocol) {}

  PacketDependency(const unsigned int &_layer, const unsigned int &_offset,
                   const unsigned int &_protocol)
      : Dependency(false, false, false, true), layer(_layer), offset(_offset) {
    protocol = std::make_pair(true, _protocol);
  }

  PacketDependency(const unsigned int &_layer, const unsigned int &_offset)
      : Dependency(false, false, false, true), layer(_layer), offset(_offset) {
    protocol.first = false;
  }

  PacketDependency(const PacketDependency &pd)
      : PacketDependency(pd.layer, pd.offset, pd.protocol) {}

  const unsigned int &get_protocol() const {
    assert(protocol.first);
    return protocol.second;
  }
  const unsigned int &get_layer() const { return layer; }
  const unsigned int &get_offset() const { return offset; }

  bool is_protocol_set() const { return protocol.first; }

  virtual std::shared_ptr<Dependency> clone() const override {
    return std::shared_ptr<Dependency>(new PacketDependency(*this));
  }

  virtual std::shared_ptr<PacketDependency> clone_packet_dependency() const {
    return std::shared_ptr<PacketDependency>(new PacketDependency(*this));
  }

  virtual std::ostream &print(std::ostream &os) const override {
    os << "layer ";
    os << layer;
    if (protocol.first) {
      os << " protocol 0x";
      os << std::hex;
      os << protocol.second;
      os << std::dec;
    }
    os << " offset ";
    os << offset;

    return os;
  }

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
                               const std::string &_description,
                               const bool &_ignore)
      : PacketDependency(_pd) {
    description = _description;
    rss_compatible = false;
    processed = true;
    packet_related = true;
    ignore = _ignore;
  }

  PacketDependencyIncompatible(const PacketDependency &_pd,
                               const std::string &_description)
      : PacketDependencyIncompatible(_pd, _description, false) {}

  PacketDependencyIncompatible(const PacketDependencyIncompatible &_pdi)
      : PacketDependency(_pdi.get_layer(), _pdi.get_offset()) {
    protocol.first = _pdi.is_protocol_set();
    if (protocol.first)
      protocol.second = _pdi.get_protocol();

    description = _pdi.get_description();
    rss_compatible = _pdi.is_rss_compatible();
    processed = _pdi.is_processed();
    packet_related = _pdi.is_packet_related();
    ignore = _pdi.should_ignore();
  }

  virtual std::shared_ptr<Dependency> clone() const override {
    return std::shared_ptr<Dependency>(new PacketDependencyIncompatible(*this));
  }

  virtual std::shared_ptr<PacketDependency> clone_packet_dependency() const override {
    return std::shared_ptr<PacketDependency>(new PacketDependencyIncompatible(*this));
  }

  virtual std::ostream &print(std::ostream &os) const override {
    PacketDependency::print(os);

    os << " [incompatible: ";
    os << description;
    os << "] ";

    return os;
  }

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
    processed = true;
    rss_compatible = true;
    packet_related = true;
  }

  PacketDependencyProcessed(const PacketDependencyProcessed &_pdp)
      : PacketDependencyProcessed(static_cast<PacketDependency>(_pdp),
                                  _pdp.get_packet_field(), _pdp.get_bytes()) {
    assert(!_pdp.should_ignore());
  }

  const R3S::R3S_pf_t &get_packet_field() const {
    assert(!ignore && "This packet field dependency should be ignored");
    return packet_field;
  }

  const unsigned int &get_bytes() const { return bytes; }

  virtual std::shared_ptr<Dependency> clone() const override {
    return std::shared_ptr<Dependency>(new PacketDependencyProcessed(*this));
  }

  virtual std::shared_ptr<PacketDependency> clone_packet_dependency() const override {
    return std::shared_ptr<PacketDependency>(new PacketDependencyProcessed(*this));
  }

  virtual std::ostream &print(std::ostream &os) const override {
    PacketDependency::print(os);

    if (!ignore) {
      os << " (";
      os << R3S::R3S_pf_to_string(packet_field);
      os << " byte ";
      os << bytes;
      os << ")";
    }

    return os;
  }

  friend bool operator==(const PacketDependencyProcessed &lhs,
                         const PacketDependencyProcessed &rhs);
};

class DependencyManager {
private:
  bool are_dependencies_sorted;

  /*
   * There should never be repeating elements inside this vector.
   *
   * I considered using an unordered_set, but it involved more work
   * than I expected. So, in order to contain my over-engineering
   * tendencies, and because this will not have many elements, I
   * decided to just use a vector.
   */
  std::vector< std::shared_ptr<Dependency> > dependencies;

public:
  DependencyManager() : are_dependencies_sorted(false) {}

  DependencyManager(const DependencyManager& manager) : DependencyManager() {
    for (auto& dependency : manager.dependencies) {
      auto copy = dependency->clone();
      dependencies.push_back(copy);
    }
  }

  const std::vector<std::shared_ptr<Dependency> >& get() const {
    return dependencies;
  }

  void sort() {
    if (are_dependencies_sorted)
      return;

    auto dependency_comparator = [](
        const std::shared_ptr<Dependency> & d1,
        const std::shared_ptr<Dependency> & d2)->bool {

      if (d1->should_ignore())
        return true;
      if (!d1->is_processed())
        return true;
      if (!d1->is_rss_compatible())
        return true;

      if (d2->should_ignore())
        return false;
      if (!d2->is_processed())
        return false;
      if (!d2->is_rss_compatible())
        return false;

      const auto &processed1 =
          dynamic_cast<PacketDependencyProcessed *>(d1.get());

      const auto &processed2 =
          dynamic_cast<PacketDependencyProcessed *>(d2.get());

      return (*processed1) < (*processed2);
    };

    std::sort(dependencies.begin(), dependencies.end(), dependency_comparator);

    are_dependencies_sorted = true;
  }

  std::vector<R3S::R3S_pf_t> get_unique_packet_fields() const {
    std::vector<R3S::R3S_pf_t> packet_fields;

    for (const auto &dependency : dependencies) {
      if (dependency->should_ignore())
        continue;

      if (!dependency->is_processed())
        continue;

      if (!dependency->is_rss_compatible())
        continue;

      const auto packet_dependency_processed =
          dynamic_cast<PacketDependencyProcessed *>(dependency.get());

      auto packet_field = packet_dependency_processed->get_packet_field();

      auto found_it =
          std::find(packet_fields.begin(), packet_fields.end(), packet_field);

      if (found_it != packet_fields.end())
        continue;

      packet_fields.push_back(packet_field);
    }

    return packet_fields;
  }

  void add_dependency(const Dependency *dependency);

  friend std::ostream &operator<<(std::ostream &os,
                                  const DependencyManager &manager);

  friend bool operator==(const DependencyManager &lhs,
                         const DependencyManager &rhs);

private:
  void process_packet_dependency(const PacketDependency *dependency);
};

} // namespace ParallelSynthesizer
