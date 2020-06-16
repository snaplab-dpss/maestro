#include <iostream>
#include <fstream>
#include <string>

#include "./parser.h"


void Parser::parse(std::string filepath) {

  // TODO: deal with errors
  std::fstream file;

  file.open(filepath.c_str(), std::ios::in); //open a file to perform read operation using file object

  if (file.is_open()){   //checking whether the file is open
    std::string tp;
    while(getline(file, tp)){ //read data from file object and put it into string.
        std::cout << tp << "\n"; //print the data of the string
    }
    file.close(); //close the file object.
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