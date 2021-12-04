#ifndef _BUCKET_H_INCLUDED_
#define _BUCKET_H_INCLUDED_

#include <stdbool.h>
#include "libvig/verified/boilerplate-util.h"

#include <stdint.h>

struct bucket {
  uint32_t value;
};

unsigned bucket_hash(void *obj);
bool bucket_eq(void *a, void *b);
void bucket_allocate(void *obj);

#define LOG_bucket(obj, p)                                                     \
  ;                                                                            \
  p("{");                                                                      \
  p("value: %d", obj->value);                                                  \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "libvig/models/str-descr.h"

extern struct str_field_descr bucket_descrs[1];
extern struct nested_field_descr bucket_nests[0];
#endif // KLEE_VERIFICATION

#endif //_BUCKET_H_INCLUDED_
