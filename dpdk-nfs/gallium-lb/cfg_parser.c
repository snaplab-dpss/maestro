#include "cfg_parser.h"

#include "nf-log.h"
#include "nf-parse.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define IP_STR_MAX_SIZE 16

// File parsing, is not really the kind of code we want to verify.
#ifdef KLEE_VERIFICATION
void fill_table_from_file(struct State *state, struct nf_config *config) {}
#else // KLEE_VERIFICATION

bool consume_until_separator(FILE *file, char *buffer, int max) {
  int i = 0;

  do {
    char ch = fgetc(file);

    if (ch == '\n' || ch == ' ' || ch == '\t' || ch == EOF) {
      buffer[i] = '\0';
      return true;
    }

    buffer[i] = ch;
    i++;
  } while (i < max);

  return false;
}

void fill_table_from_file(struct State *state, struct nf_config *config) {
  if (config->table_fname[0] == '\0') {
    // No static config
    return;
  }

  FILE *file = fopen(config->table_fname, "r");
  if (file == NULL) {
    rte_exit(EXIT_FAILURE, "Error opening the static config file: %s",
             config->table_fname);
  }

  uint32_t n_backends = 0;

  while (!feof(file)) {
    if (n_backends >= config->num_backends) {
      rte_exit(EXIT_FAILURE, "Too many backends, expected: %d",
               config->num_backends);
    }

    char backend_ip[IP_STR_MAX_SIZE];

    if (!consume_until_separator(file, backend_ip, IP_STR_MAX_SIZE)) {
      NF_INFO("Cannot read backend IP from file.");
      goto finally;
    }

    struct Backend *backend = 0;
    vector_borrow(state->backends, n_backends, (void **)&backend);

    if (!nf_parse_ipv4addr(backend_ip, &backend->ip)) {
      NF_INFO("Invalid backend IP: %s, skip", backend_ip);
      continue;
    }

    vector_return(state->backends, n_backends, backend);
    n_backends++;

    NF_DEBUG("Added lb backend: %u.%u.%u.%u", (backend->ip >> 0) & 0xff,
             (backend->ip >> 8) & 0xff, (backend->ip >> 16) & 0xff,
             (backend->ip >> 24) & 0xff);
  }

finally:
  fclose(file);
}
#endif