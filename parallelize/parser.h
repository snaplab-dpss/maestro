#pragma once

#include "libvig_access.h"
#include "constraint.h"

#include <z3.h>
#include <vector>

namespace ParallelSynthesizer {
namespace ConstraintsGenerator {
namespace Tokens {

const std::string ACCESS_START = "BEGIN ACCESS";
const std::string ACCESS_END = "END ACCESS";
const std::string CONSTRAINT_START = "BEGIN CONSTRAINT";
const std::string CONSTRAINT_END = "END CONSTRAINT";
const std::string ID = "id";
const std::string DEVICE = "device";
const std::string OBJECT = "object";
const std::string LAYER = "layer";
const std::string PROTOCOL = "proto";
const std::string DEPENDENCY = "dep";

}

class Parser {
  
private:
  Z3_context &ctx;
  std::vector<LibvigAccess> accesses;
  std::vector<Constraint> constraints;

private:
  LibvigAccess& get_or_push_unique_access(const LibvigAccess& access);

  std::istringstream consume_token(std::string& line, const std::string& token);
  void parse_access(std::vector<std::string>& state_content);

public:
  Parser (Z3_context &_ctx) : ctx(_ctx) { }
  
  const std::vector<LibvigAccess>& get_accesses()  const { return accesses; }

  const std::vector<ConstraintsGenerator::Constraint>&
    get_constraints() const { return constraints; }

  void parse(std::string filepath);
};

}
}

/*
typedef struct {
  libvig_accesses_t accesses;
  constraints_t     constraints;
} parsed_data_t;

typedef enum {
  INIT,
  ACCESS,
  CONSTRAINT,
  SMT
} parser_state_t;

void parsed_data_init(parsed_data_t *data);
void parse_libvig_access_file(char *path, parsed_data_t *data, Z3_context ctx);
*/
