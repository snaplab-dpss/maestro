#ifndef _SOURCE_KEY_GEN_H_INCLUDED_
#define _SOURCE_KEY_GEN_H_INCLUDED_

#include <stdbool.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/ether.h"
#include "libvig/verified/vigor-time.h"

struct SourceKey {
  uint32_t src_ip;
  uint16_t total;
};

unsigned SourceKey_hash(void *obj);
bool SourceKey_eq(void *a, void *b);
void SourceKey_allocate(void *obj);

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "libvig/models/str-descr.h"

extern struct str_field_descr SourceKey_descrs[2];
extern struct nested_field_descr SourceKey_nests[0];
#endif // KLEE_VERIFICATION

#endif //_SOURCE_KEY_GEN_H_INCLUDED_
