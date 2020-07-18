#pragma once

#include "libvig_access.h"
#include "constraint.h"
#include "tokens.h"

#include <vector>

namespace ParallelSynthesizer {

class Parser {
  
private:
  std::vector<std::string> state_content;
  unsigned line_counter;

  std::vector<LibvigAccess>  accesses;
  std::vector<RawConstraint> raw_constraints;


private:
  LibvigAccess& get_or_push_unique_access(const LibvigAccess& access);
  void push_unique_raw_constraint(const RawConstraint& raw_constraint);

  std::istringstream consume_token(const std::string& token);
  void parse_access();
  void parse_constraint();

public:
  Parser() : line_counter(0) {}

  const std::vector<LibvigAccess>& get_accesses() const { return accesses; }

  const std::vector<RawConstraint>&
    get_raw_constraints() const { return raw_constraints; }

  void parse(std::string filepath);
  void report();
};

}
