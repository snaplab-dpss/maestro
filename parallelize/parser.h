#pragma once

#include "./libvig_access.h"
#include "./constraint.h"

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