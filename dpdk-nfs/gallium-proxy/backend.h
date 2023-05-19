#ifndef __BACKEND_H__
#define __BACKEND_H__

#include <stdint.h>
#include <stdbool.h>

#include "lib/verified/boilerplate-util.h"

struct Backend {
  uint32_t ip;
  uint16_t port;
};

unsigned backend_hash(void* obj);
bool backend_eq(void* a, void* b);
void backend_allocate(void* obj);

#ifdef KLEE_VERIFICATION
#  include <klee/klee.h>
#  include "lib/models/str-descr.h"

extern struct str_field_descr backend_descrs[2];
extern struct nested_field_descr backend_nests[0];
#endif//KLEE_VERIFICATION

#endif