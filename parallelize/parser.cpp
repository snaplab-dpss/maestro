#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <algorithm>
#include <numeric>

#include "parser.h"

namespace ParallelSynthesizer {
namespace ConstraintsGenerator {

enum State {
  Init,
  Access,
  Constraint,
  Statement
};

LibvigAccess& Parser::get_or_push_unique_access(const LibvigAccess &access) {
  auto it = std::find(accesses.begin(), accesses.end(), access);

  if (it == accesses.end()) {
    accesses.emplace_back(access);
    return accesses.back();
  }

  return *it;
}

void Parser::push_unique_raw_constraint(const RawConstraint& raw_constraint) {
  auto it = std::find(raw_constraints.begin(), raw_constraints.end(), raw_constraint);

  if (it == raw_constraints.end())
    raw_constraints.push_back(raw_constraint);
}

std::istringstream Parser::consume_token(std::string& line, const std::string& token) {
  auto found = line.find(token);
  
  if (found == std::string::npos) {
    std::cerr << "[ERORR] Token not found." << '\n';
    std::cerr << "        Input: " << line << '\n';
    std::cerr << "        Missing token: " << token << std::endl;

    exit(1);
  }

  return std::istringstream(line.substr(found + token.length()));
}

void Parser::parse_access(std::vector<std::string>& state_content) {
  if (state_content.size() < 3)  {
    std::cerr << "[ERROR] Missing parameters of access component" << std::endl;
    exit(1);
  }

  unsigned int id;
  unsigned int device;
  unsigned int object;

  std::istringstream iss;
  
  iss = consume_token(state_content[0], Tokens::ID);
  iss >> std::ws >> id;

  iss = consume_token(state_content[1], Tokens::DEVICE);
  iss >> std::ws >> device;

  iss = consume_token(state_content[2], Tokens::OBJECT);
  iss >> std::ws >> object;

  state_content.erase(state_content.begin(), state_content.begin() + 3);

  if (state_content.size() == 0)
    return;
  
  LibvigAccess& access = get_or_push_unique_access(LibvigAccess(id, device, object));

  unsigned int layer;
  unsigned int protocol;

  iss = consume_token(state_content[0], Tokens::LAYER);
  iss >> std::ws >> layer;

  iss = consume_token(state_content[1], Tokens::PROTOCOL);
  iss >> std::ws >> protocol;

  state_content.erase(state_content.begin(), state_content.begin() + 2);

  for (auto &content : state_content) {
    unsigned int offset;

    iss = consume_token(content, Tokens::DEPENDENCY);
    iss >> std::ws >> offset;
  
    PacketDependency dependency(layer, protocol, offset);
    access.add_dependency(dependency);
  }
}

void Parser::parse_constraint(std::vector<std::string>& state_content) {
  if (state_content.size() < 5)  {
    std::cerr << "[ERROR] Missing parameters of constraint component" << std::endl;
    exit(1);
  }

  unsigned int first;
  unsigned int second;
  std::string  expression;

  std::istringstream iss;

  iss = consume_token(state_content[0], Tokens::FIRST);
  iss >> std::ws >> first;

  iss = consume_token(state_content[1], Tokens::SECOND);
  iss >> std::ws >> second;

  if (state_content[2] != Tokens::STATEMENT_START) {
    std::cerr << "[ERROR] Missing start statement on constraint component" << std::endl;
    exit(1);
  }

  state_content.erase(state_content.begin(), state_content.begin() + 3);

  expression = std::accumulate(
    state_content.begin() + 3,
    state_content.end() - 1,
    std::string("")
  );

  RawConstraint raw_constraint(first, second, expression);
  push_unique_raw_constraint(raw_constraint);  
}

void Parser::parse(std::string filepath) {
  // TODO: deal with errors
  std::fstream file;

  file.open(filepath.c_str(), std::ios::in);

  if (!file.is_open()) {
    std::cerr << "Error trying to open file." << std::endl;
    exit(1);
  }

  std::string line;
  State state(State::Init);
  std::vector<std::string> state_content;

  while (getline(file, line)) {

    if (line == Tokens::ACCESS_END) {
      parse_access(state_content);
      state_content.clear();
      state = State::Init;
    }

    else if (line == Tokens::CONSTRAINT_END) {
      parse_constraint(state_content);
      state_content.clear();
      state = State::Init;
    }

    else if (line == Tokens::ACCESS_START) {
      state = State::Access;
    }

    else if (line == Tokens::CONSTRAINT_START) {
      state = State::Constraint;
    }

    else
      state_content.push_back(line);
  }

  file.close();
}

}
}

/*
void parsed_data_init(parsed_data_t *data) {
  libvig_accesses_init(&(data->accesses));
  constraints_init(&(data->constraints));
}

void warn(const char *description) { printf("[WARNING] %s\n", description); }

void invalid_rss_opt(const char *pf) {
  char pre[21] = "Invalid RSS option: ";

  unsigned pre_sz = strlen(pre);
  unsigned pf_sz = strlen(pf);
  unsigned msg_sz = pre_sz + pf_sz + 1;

  char *msg = (char *)malloc(sizeof(char) * msg_sz);
  snprintf(msg, msg_sz, "%s%s", pre, pf);

  warn(msg);
  free(msg);
}

char *consume_token(char *str, const char *token) {
  char *str_ptr;
  bool result = strncmp(str, token, strlen(token)) == 0;

  if (!result)
    return NULL;

  str_ptr = str + strlen(token);
  while (*str_ptr == ' ')
    str_ptr++;

  return str_ptr;
}

void parse_libvig_access_file(char *path, parsed_data_t *data, Z3_context ctx) {
  FILE *fp;

  char *line = NULL;
  char *line_ptr;
  size_t len = 0;
  ssize_t read_len;

  libvig_access_t curr_access;
  smt_t curr_smt;

  parser_state_t state = INIT;

  if ((fp = fopen(path, "r")) == NULL) {
    printf("[ERROR] Unable to open %s\n", path);
    exit(1);
  }

  line = NULL;
  while ((read_len = getline(&line, &len, fp)) > 0) {
    if (len == 1)
      break;
    line[read_len - 1] = 0;

    switch (state) {
    case INIT:
      if (consume_token(line, "BEGIN ACCESS")) {
        deps_init(&(curr_access.deps));
        state = ACCESS;
      } else if (consume_token(line, "BEGIN CONSTRAINT")) {
        state = CONSTRAINT;
      } else {
        printf("[ERROR] Unknown token in state INIT: \"%s\"\n", line);
        exit(1);
      }

      break;

    case ACCESS:
      if (consume_token(line, "END ACCESS")) {
        if (curr_access.deps.sz)
          libvig_accesses_append_unique(curr_access, &(data->accesses));
        state = INIT;
      } else if (((line_ptr = consume_token(line, "id")))) {
        sscanf(line_ptr, "%u", &curr_access.id);

      } else if ((line_ptr = consume_token(line, "device"))) {
        sscanf(line_ptr, "%u", &curr_access.device);

      } else if ((line_ptr = consume_token(line, "object"))) {
        sscanf(line_ptr, "%u", &curr_access.obj);

      } else if ((line_ptr = consume_token(line, "layer"))) {
        sscanf(line_ptr, "%u", &curr_access.layer);

      } else if ((line_ptr = consume_token(line, "proto"))) {
        sscanf(line_ptr, "%u", &curr_access.proto);

      } else if ((line_ptr = consume_token(line, "dep"))) {
        unsigned offset;
        sscanf(line_ptr, "%u", &offset);

        dep_t dep = dep_from_offset(offset, curr_access);
        deps_append_unique(&(curr_access.deps), dep);

      } else {
        printf("[ERROR] Unknown token in state ACCESS: \"%s\"\n", line);
        exit(1);
      }

      break;

    case CONSTRAINT:
      if (consume_token(line, "END CONSTRAINT")) {
        constraints_append(&(data->constraints), data->accesses, curr_smt, ctx);
        free(curr_smt.query);
        state = INIT;

      } else if (consume_token(line, "BEGIN SMT")) {
        curr_smt.query = (char *)malloc(sizeof(char));
        curr_smt.query[0] = '\0';
        curr_smt.query_sz = 1;
        state = SMT;

      } else if ((line_ptr = consume_token(line, "first"))) {
        sscanf(line_ptr, "%u", &curr_smt.first_access_id);

      } else if ((line_ptr = consume_token(line, "second"))) {
        sscanf(line_ptr, "%u", &curr_smt.second_access_id);

      } else {
        printf("[ERROR] Unknown token in state CONSTRAINT: \"%s\"\n", line);
        exit(1);
      }

      break;

    case SMT:
      if (consume_token(line, "END SMT")) {
        state = CONSTRAINT;
      } else {
        curr_smt.query = (char *)realloc(
            curr_smt.query, sizeof(char) * (curr_smt.query_sz + read_len));

        strncpy(curr_smt.query + curr_smt.query_sz - 1, line, read_len - 1);

        curr_smt.query_sz += read_len;
        curr_smt.query[curr_smt.query_sz - 2] = '\n';
        curr_smt.query[curr_smt.query_sz - 1] = '\0';
      }

      break;

    default:
      printf("[ERROR] Unknown state: (%u)\n", state);
      exit(1);
    }
  }

  free(line);
  fclose(fp);

  if (state != INIT) {
    printf("[ERROR] Final state not INIT: (%u)\n", state);
    exit(1);
  }
}
*/