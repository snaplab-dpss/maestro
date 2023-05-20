#include "cfg_parser.h"

#include "nf-log.h"
#include "nf-parse.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define IP_STR_MAX_SIZE 16
#define PORT_STR_MAX_SIZE 6
#define PROTO_STR_MAX_SIZE 4
#define DEVICE_STR_MAX_SIZE 6

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

    char device[DEVICE_STR_MAX_SIZE];
    char src_addr[IP_STR_MAX_SIZE];
    char dst_addr[IP_STR_MAX_SIZE];
    char src_port[PORT_STR_MAX_SIZE];
    char dst_port[PORT_STR_MAX_SIZE];
    char proto[PROTO_STR_MAX_SIZE];

    if (!consume_until_separator(file, device, DEVICE_STR_MAX_SIZE)) {
      NF_INFO("Cannot read device from file.");
      goto finally;
    }

    if (!consume_until_separator(file, src_addr, IP_STR_MAX_SIZE)) {
      NF_INFO("Cannot read source address from file.");
      goto finally;
    }

    if (!consume_until_separator(file, src_port, PORT_STR_MAX_SIZE)) {
      NF_INFO("Cannot read source port from file.");
      goto finally;
    }

    if (!consume_until_separator(file, dst_addr, IP_STR_MAX_SIZE)) {
      NF_INFO("Cannot read destination address from file.");
      goto finally;
    }

    if (!consume_until_separator(file, dst_port, PORT_STR_MAX_SIZE)) {
      NF_INFO("Cannot read destination port from file.");
      goto finally;
    }

    if (!consume_until_separator(file, proto, PROTO_STR_MAX_SIZE)) {
      NF_INFO("Cannot read protocol from file.");
      goto finally;
    }

    struct Flow *flow = 0;

    vector_borrow(state->entries, n_entries, (void **)&flow);

    if (!nf_parse_device(device, &flow->device)) {
      NF_INFO("Invalid device: %s, skip", device);
      continue;
    }

    if (!nf_parse_ipv4addr(src_addr, &flow->src_addr)) {
      NF_INFO("Invalid source address: %s, skip", src_addr);
      continue;
    }

    if (!nf_parse_ipv4addr(dst_addr, &flow->dst_addr)) {
      NF_INFO("Invalid destination address: %s, skip", dst_addr);
      continue;
    }

    if (!nf_parse_port(src_port, &flow->src_port)) {
      NF_INFO("Invalid source port: %s, skip", src_port);
      exit(1);
      continue;
    }

    if (!nf_parse_port(dst_port, &flow->dst_port)) {
      NF_INFO("Invalid destination port: %s, skip", dst_port);
      exit(1);
      continue;
    }

    if (!nf_parse_proto(proto, &flow->proto)) {
      NF_INFO("Invalid protocol: %s, skip", proto);
      exit(1);
      continue;
    }

    map_put(state->table, flow, n_entries);
    vector_return(state->entries, n_entries, flow);

    n_entries++;

    NF_DEBUG(
        "Allow flow: [device=%u] %u.%u.%u.%u:%u => %u.%u.%u.%u:%u proto=%u",
        flow->device, (flow->src_addr >> 0) & 0xff,
        (flow->src_addr >> 8) & 0xff, (flow->src_addr >> 16) & 0xff,
        (flow->src_addr >> 24) & 0xff, rte_be_to_cpu_16(flow->src_port),
        (flow->dst_addr >> 0) & 0xff, (flow->dst_addr >> 8) & 0xff,
        (flow->dst_addr >> 16) & 0xff, (flow->dst_addr >> 24) & 0xff,
        rte_be_to_cpu_16(flow->dst_port), flow->proto);
  }

finally:
  fclose(file);
}
#endif