#pragma once

#include <assert.h>
#include <memory>

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

    Dependency(bool _ignore, bool _rss_compatible, bool _processed, bool _packet_related)
        : ignore(_ignore), rss_compatible(_rss_compatible), processed(_processed), packet_related(_packet_related) {}

    virtual std::ostream& print(std::ostream& os) const = 0;

public:
    bool should_ignore() const { return ignore; }
    bool is_rss_compatible() const { return rss_compatible; }
    bool is_processed() const { return processed; }
    bool is_packet_related() const { return packet_related; }

    virtual std::unique_ptr<const Dependency> get_unique() const = 0;
    virtual Dependency* clone() const = 0;

    friend std::ostream& operator<<(std::ostream& os, const Dependency& dependency);

    virtual ~Dependency() {}
};

class PacketDependency : public Dependency {

private:
  unsigned int layer;
  unsigned int protocol;
  unsigned int offset;

public:
  PacketDependency(const unsigned int &_layer,
                   const unsigned int &_protocol,
                   const unsigned int &_offset)
      : Dependency(false, false, false, true), layer(_layer), protocol(_protocol), offset(_offset) {}

  PacketDependency(const PacketDependency &pd)
      : PacketDependency(pd.get_layer(), pd.get_protocol(), pd.get_offset()) {}

  const unsigned int &get_layer() const { return layer; }
  const unsigned int &get_protocol() const { return protocol; }
  const unsigned int &get_offset() const { return offset; }

  virtual std::unique_ptr<const Dependency> get_unique() const override {
    return std::unique_ptr<const Dependency>(new PacketDependency(*this));
  }

  virtual PacketDependency* clone() const override {
      return new PacketDependency(*this);
  }

  virtual std::ostream& print(std::ostream& os) const override {
      os << "layer ";
      os << layer;
      os << " protocol 0x";
      os << std::hex << protocol;
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
                               const bool& _ignore)
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
      : PacketDependency(_pdi.get_layer(), _pdi.get_protocol(), _pdi.get_offset()) {
    description = _pdi.get_description();
    rss_compatible = _pdi.is_rss_compatible();
    processed = _pdi.is_processed();
    packet_related = _pdi.is_packet_related();
    ignore = _pdi.should_ignore();
  }

  virtual PacketDependencyIncompatible* clone() const override {
      return new PacketDependencyIncompatible(*this);
  }

  std::unique_ptr<const Dependency> get_unique() const override {
    return std::unique_ptr<const Dependency>(new PacketDependencyIncompatible(*this));
  }

  virtual std::ostream& print(std::ostream& os) const override {
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

  virtual PacketDependencyProcessed* clone() const override {
      return new PacketDependencyProcessed(*this);
  }

  std::unique_ptr<const Dependency> get_unique() const override {
    return std::unique_ptr<const Dependency>(new PacketDependencyProcessed(*this));
  }

  virtual std::ostream& print(std::ostream& os) const override {
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

} // namespace ParallelSynthesizer
