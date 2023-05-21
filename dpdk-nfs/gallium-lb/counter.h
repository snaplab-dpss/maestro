#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "lib/verified/boilerplate-util.h"

struct Counter {
  uint32_t value;
};

void counter_allocate(void *obj);

#ifdef KLEE_VERIFICATION
#include "lib/models/str-descr.h"
#include <klee/klee.h>

extern struct str_field_descr counter_descrs[1];
extern struct nested_field_descr counter_nests[0];

bool flows_counter_invariant(void *counter, int index, void *state);
bool backends_counter_invariant(void *counter, int index, void *state);
#endif // KLEE_VERIFICATION