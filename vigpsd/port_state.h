#ifndef _PORT_STATE_GEN_H_INCLUDED_
#define _PORT_STATE_GEN_H_INCLUDED_

#include <stdbool.h>
#include "libvig/verified/boilerplate-util.h"

#include "libvig/verified/ether.h"

#include <stdint.h>

struct port_state {
  bool touched;
};

unsigned port_state_hash(void *obj);
bool port_state_eq(void *a, void *b);
void port_state_allocate(void *obj);

#define LOG_PORT(obj, p)                                                       \
  ;                                                                            \
  p("{");                                                                      \
  p("touched: %d", obj->touched);                                              \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "libvig/models/str-descr.h"

extern struct str_field_descr port_state_descrs[1];
extern struct nested_field_descr port_state_nests[0];
#endif // KLEE_VERIFICATION

#endif //_PORT_STATE_GEN_H_INCLUDED_
