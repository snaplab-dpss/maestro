#ifndef _DYN_VALUE_H_INCLUDED_
#define _DYN_VALUE_H_INCLUDED_

#include <stdint.h>
#include <stdbool.h>

#include "lib/verified/boilerplate-util.h"
#include "lib/verified/ether.h"

#define DEFAULT_DYNAMICVALUE DynamicValuec(0)

struct DynamicValue {
  uint16_t device;
};

unsigned DynamicValue_hash(void* obj);
bool DynamicValue_eq(void* a, void* b);
void DynamicValue_allocate(void* obj);

#define LOG_DYNAMICVALUE(obj, p)  \
  ;                               \
  p("{");                         \
  p("device: %d", (obj)->device); \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "lib/models/str-descr.h"

extern struct str_field_descr DynamicValue_descrs[1];
extern struct nested_field_descr DynamicValue_nests[0];
#endif  // KLEE_VERIFICATION

#endif  //_DYN_VALUE_H_INCLUDED_
