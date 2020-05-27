#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>

#include <r3s.h>
#include <z3.h>

#include "./libvig_access.h"
#include "./constraint.h"

typedef struct {
  libvig_accesses_t accesses;
  constraints_t constraints;
} parsed_data_t;

typedef enum {
  INIT,
  ACCESS,
  CONSTRAINT,
  SMT
} parser_state_t;

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

int main(int argc, char *argv[]) {

  if (argc < 2) {
    printf("[ERROR] Missing arguments.");
    printf("Please provide a libvig-access-out.txt file location\n");
    return 1;
  }

  char *libvig_access_out = argv[1];

  parsed_data_t data;
  parsed_data_init(&data);

  R3S_cfg_t cfg;
  R3S_cfg_init(&cfg);

  parse_libvig_access_file(libvig_access_out, &data, cfg.ctx);

  unsigned curr_device;
  bool curr_device_set = false;

  for (unsigned i = 0; i < data.accesses.sz; i++) {
    printf("Device %u\n", data.accesses.accesses[i].device);
    printf("Object %u\n", data.accesses.accesses[i].obj);

    for (unsigned idep = 0; idep < data.accesses.accesses[i].deps.sz; idep++) {
      if (data.accesses.accesses[i].deps.deps[idep].pf_is_set)
        printf("    %s\n",
               R3S_pf_to_string(data.accesses.accesses[i].deps.deps[idep].pf));
      else
        printf("  * %s\n",
               data.accesses.accesses[i].deps.deps[idep].error_descr);
    }
  }

  for (unsigned i = 0; i < data.constraints.sz; i++) {
    printf("\n===========================\n");
    printf("Constraint %u\n", i);
    printf("ast: %s\n", Z3_ast_to_string(cfg.ctx,
                                         data.constraints.cnstrs[i].cnstr));
    printf("first access id: %u\n", data.constraints.cnstrs[i].first->id);
    printf("second access id: %u\n", data.constraints.cnstrs[i].second->id);

    for (unsigned j = 0; j < data.constraints.cnstrs[i].pfs.sz; j++) {
      printf("pf %u\n", j);
      printf("ast: %s\n", Z3_ast_to_string(cfg.ctx,
                                         data.constraints.cnstrs[i].pfs.pfs[j].select));
      printf("index: %u\n", data.constraints.cnstrs[i].pfs.pfs[j].index);      
    }
  }

  constraints_destroy(&(data.constraints));
  libvig_accesses_destroy(&(data.accesses));
}