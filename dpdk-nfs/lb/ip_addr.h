#ifndef _IP_ADDR_H_INCLUDED_
#define _IP_ADDR_H_INCLUDED_

#include <stdint.h>
#include <stdbool.h>

#include "lib/verified/boilerplate-util.h"
#include "lib/verified/ether.h"

#define DEFAULT_IP_ADDR ip_addrc(0)

struct ip_addr {
  uint32_t addr;
};

unsigned ip_addr_hash(void* obj);
bool ip_addr_eq(void* a, void* b);
void ip_addr_allocate(void* obj);

#define LOG_IP_ADDR(obj, p)   \
  ;                           \
  p("{");                     \
  p("addr: %d", (obj)->addr); \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "lib/models/str-descr.h"

extern struct str_field_descr ip_addr_descrs[1];
extern struct nested_field_descr ip_addr_nests[0];
#endif  // KLEE_VERIFICATION

#endif  //_IP_ADDR_H_INCLUDED_
