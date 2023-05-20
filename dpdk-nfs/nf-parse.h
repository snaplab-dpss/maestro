#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <rte_byteorder.h>
#include <rte_ether.h>

bool nf_parse_etheraddr(const char *str, struct rte_ether_addr *addr);
bool nf_parse_ipv4addr(const char *str, uint32_t *addr);
bool nf_parse_port(const char *str, uint16_t *port);
bool nf_parse_proto(const char *str, uint8_t *proto);
bool nf_parse_device(const char *str, uint16_t *device);