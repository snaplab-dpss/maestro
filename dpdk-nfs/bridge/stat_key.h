#ifndef _STAT_KEY_H_INCLUDED_
#define _STAT_KEY_H_INCLUDED_

#include <stdint.h>
#include <stdbool.h>

#include <rte_ether.h>

#include "lib/verified/boilerplate-util.h"
#include "lib/verified/ether.h"

struct StaticKey {
  struct rte_ether_addr addr;
  uint16_t device;
};

#define DEFAULT_STATICKEY StaticKeyc(rte_ether_addrc(0, 0, 0, 0, 0, 0), 0)

unsigned StaticKey_hash(void* obj);
bool StaticKey_eq(void* a, void* b);
void StaticKey_allocate(void* obj);

#define LOG_STATICKEY(obj, p)       \
  ;                                 \
  p("{");                           \
  p("addr:");                       \
  LOG_RTE_ETHER_ADDR(&(obj)->addr); \
  p("device: %d", (obj)->device);   \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "lib/models/str-descr.h"

extern struct str_field_descr StaticKey_descrs[2];
extern struct nested_field_descr StaticKey_nests[1];
#endif  // KLEE_VERIFICATION

#endif  //_STAT_KEY_H_INCLUDED_
