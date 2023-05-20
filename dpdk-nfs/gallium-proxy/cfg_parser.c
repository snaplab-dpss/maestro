#include "cfg_parser.h"

#include "nf-log.h"
#include "nf-parse.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define IP_STR_MAX_SIZE 16
#define PORT_STR_MAX_SIZE 6

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

  uint32_t n_entries = 0;

  while (!feof(file)) {
    if (n_entries >= config->capacity) {
      rte_exit(EXIT_FAILURE, "Too many static rules, max: %d",
               config->capacity);
    }

    char dst_port[PORT_STR_MAX_SIZE];
    char backend_ip[IP_STR_MAX_SIZE];
    char backend_port[PORT_STR_MAX_SIZE];

    if (!consume_until_separator(file, dst_port, PORT_STR_MAX_SIZE)) {
      NF_INFO("Cannot read destination port from file.");
      goto finally;
    }

    if (!consume_until_separator(file, backend_ip, IP_STR_MAX_SIZE)) {
      NF_INFO("Cannot read backend IP from file.");
      goto finally;
    }

    if (!consume_until_separator(file, backend_port, PORT_STR_MAX_SIZE)) {
      NF_INFO("Cannot read backend port from file.");
      goto finally;
    }

    struct Entry *entry = 0;
    struct Backend *backend = 0;

    vector_borrow(state->entries, n_entries, (void **)&entry);
    vector_borrow(state->values, n_entries, (void **)&backend);

    if (!nf_parse_port(dst_port, &entry->port)) {
      NF_INFO("Invalid destination port: %s, skip", dst_port);
      exit(1);
      continue;
    }

    if (!nf_parse_ipv4addr(backend_ip, &backend->ip)) {
      NF_INFO("Invalid backend IP: %s, skip", backend_ip);
      continue;
    }

    if (!nf_parse_port(backend_port, &backend->port)) {
      NF_INFO("Invalid backend port: %s, skip", backend_port);
      continue;
    }

    map_put(state->table, entry, n_entries);

    vector_return(state->entries, n_entries, entry);
    vector_return(state->values, n_entries, backend);

    n_entries++;

    NF_DEBUG("Added proxy entry: %u => %u.%u.%u.%u:%u",
             rte_be_to_cpu_16(entry->port), (backend->ip >> 0) & 0xff,
             (backend->ip >> 8) & 0xff, (backend->ip >> 16) & 0xff,
             (backend->ip >> 24) & 0xff, rte_be_to_cpu_16(backend->port));
  }

finally:
  fclose(file);
}
#endif