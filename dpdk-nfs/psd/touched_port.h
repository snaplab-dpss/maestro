#ifndef _TOUCHED_PORT_GEN_H_INCLUDED_
#define _TOUCHED_PORT_GEN_H_INCLUDED_

#include <stdbool.h>
#include "lib/verified/boilerplate-util.h"

#include "lib/verified/ether.h"

#include <stdint.h>

struct TouchedPort {
  uint32_t src;
  uint16_t port;
};

bool touched_port_eq(void *a, void *b);
void touched_port_allocate(void *obj);
unsigned touched_port_hash(void *obj);

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "lib/models/str-descr.h"

extern struct str_field_descr touched_port_descrs[2];
extern struct nested_field_descr touched_port_nests[0];
#endif  // KLEE_VERIFICATION

#endif  //_TOUCHED_PORT_GEN_H_INCLUDED_
