#ifndef __ENTRY_H__
#define __ENTRY_H__

#include <stdint.h>
#include <stdbool.h>

#include "lib/verified/boilerplate-util.h"

struct Entry {
  uint16_t port;
};

unsigned entry_hash(void* obj);
bool entry_eq(void* a, void* b);
void entry_allocate(void* obj);

#ifdef KLEE_VERIFICATION
#  include <klee/klee.h>
#  include "lib/models/str-descr.h"

extern struct str_field_descr entry_descrs[1];
extern struct nested_field_descr entry_nests[0];
#endif//KLEE_VERIFICATION

#endif