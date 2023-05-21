#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lib/verified/boilerplate-util.h"

struct Entry {
  uint16_t port;
};

unsigned entry_hash(void *obj);
bool entry_eq(void *a, void *b);
void entry_allocate(void *obj);

#ifdef KLEE_VERIFICATION
#include "lib/models/str-descr.h"
#include <klee/klee.h>

extern struct str_field_descr entry_descrs[1];
extern struct nested_field_descr entry_nests[0];
#endif // KLEE_VERIFICATION