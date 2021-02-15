#include "nf-rss.h"

void reta_from_file(uint16_t reta[ETH_RSS_RETA_SIZE_512]) {
  int lcores = rte_lcore_count();

  FILE* fp;
  char* line = NULL;
  char* delim;
  size_t num_len;
  char* number;

  size_t len = 0;
  ssize_t read;

  fp = fopen("./lut.txt", "r");
  if (fp == NULL) {
    rte_exit(EXIT_FAILURE, "lut.txt not found");
  }

  int reta_lcores = 2;
  while ((read = getline(&line, &len, fp)) != -1) {
    if (reta_lcores == lcores) {
      break;
    }
    reta_lcores++;
  }
  fclose(fp);

  delim = line;
  number = (char*) malloc(sizeof(char) * read);
  for (uint16_t bucket = 0; bucket < ETH_RSS_RETA_SIZE_512; bucket++) {
    num_len = 0;
    while (*delim != ' ' && *delim != '\n') { number[num_len] = *delim; delim++; num_len++; }
    delim++;
    number[num_len] = '\0';

    reta[bucket] = atoi(number);
  }

  free(number);
  free(line);
}

void set_reta(uint16_t device, uint16_t reta[ETH_RSS_RETA_SIZE_512]) {
  struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(device, &dev_info);

  /* RETA setting */
  memset(reta_conf, 0, sizeof(reta_conf));

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
      reta_conf[bucket / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
  }

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
      uint32_t reta_id  = bucket / RTE_RETA_GROUP_SIZE;
      uint32_t reta_pos = bucket % RTE_RETA_GROUP_SIZE;
      reta_conf[reta_id].reta[reta_pos] = reta[bucket];
  }

  /* RETA update */
  rte_eth_dev_rss_reta_update(device, reta_conf, dev_info.reta_size);
}
