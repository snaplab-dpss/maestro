#ifndef _ip_addr_GEN_H_INCLUDED_
#define _ip_addr_GEN_H_INCLUDED_

#include <stdbool.h>
#include "libvig/verified/boilerplate-util.h"

#include "libvig/verified/ether.h"

#define DEFAULT_ip_addr ip_addrc(0)

#include <stdint.h>

struct ip_addr {
  uint32_t addr;
};

unsigned ip_addr_hash(void *obj);
bool ip_addr_eq(void *a, void *b);
void ip_addr_allocate(void *obj);

#define LOG_IP_ADDR(obj, p)                                                    \
  ;                                                                            \
  p("{");                                                                      \
  p("addr: %d", obj->addr);                                                    \
  p("}");

#ifdef KLEE_VERIFICATION
#  include <klee/klee.h>
#  include "libvig/models/str-descr.h"

extern struct str_field_descr ip_addr_descrs[1];
extern struct nested_field_descr ip_addr_nests[0];
#endif // KLEE_VERIFICATION

#endif //_ip_addr_GEN_H_INCLUDED_
