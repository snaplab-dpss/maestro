#include "nf-parse.h"

bool nf_parse_etheraddr(const char *str, struct rte_ether_addr *addr) {
  return sscanf(str, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
                addr->addr_bytes + 0, addr->addr_bytes + 1,
                addr->addr_bytes + 2, addr->addr_bytes + 3,
                addr->addr_bytes + 4, addr->addr_bytes + 5) == 6;
}

bool nf_parse_ipv4addr(const char *str, uint32_t *addr) {
  uint8_t a, b, c, d;
  if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) == 4) {
    *addr = ((uint32_t)a << 0) | ((uint32_t)b << 8) | ((uint32_t)c << 16) |
            ((uint32_t)d << 24);
    return true;
  }
  return false;
}

bool nf_parse_port(const char *str, uint16_t *port) {
  uint16_t p;
  if (sscanf(str, "%" SCNu16, &p) == 1) {
    *port = rte_be_to_cpu_16(p);
    return true;
  }
  return false;
}

bool nf_parse_proto(const char *str, uint8_t *proto) {
  return sscanf(str, "%" SCNu8, proto) == 1;
}

bool nf_parse_device(const char *str, uint16_t *device) {
  return sscanf(str, "%" SCNu16, device) == 1;
}