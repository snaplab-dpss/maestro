#ifndef _LB_BACKEND_H_INCLUDED_
#define _LB_BACKEND_H_INCLUDED_

#include <stdint.h>
#include <stdbool.h>

#include <rte_ether.h>

#include "lib/verified/boilerplate-util.h"
#include "lib/verified/ether.h"

struct LoadBalancedBackend {
  uint16_t nic;
  struct rte_ether_addr mac;
  uint32_t ip;
};

#define DEFAULT_LOADBALANCEDBACKEND \
  LoadBalancedBackendc(0, rte_ether_addrc(0, 0, 0, 0, 0, 0), 0)

unsigned LoadBalancedBackend_hash(void* obj);
bool LoadBalancedBackend_eq(void* a, void* b);
void LoadBalancedBackend_allocate(void* obj);

#define LOG_LOADBALANCEDBACKEND(obj, p) \
  ;                                     \
  p("{");                               \
  p("nic: %d", (obj)->nic);             \
  p("mac:");                            \
  LOG_RTE_ETHER_ADDR(&(obj)->mac);      \
  p("ip: %d", (obj)->ip);               \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "lib/models/str-descr.h"

extern struct str_field_descr LoadBalancedBackend_descrs[3];
extern struct nested_field_descr LoadBalancedBackend_nests[1];
#endif  // KLEE_VERIFICATION

#endif  //_LB_BACKEND_H_INCLUDED_
