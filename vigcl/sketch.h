#ifndef _SKETCH_H_INCLUDED_
#define _SKETCH_H_INCLUDED_

#include <stdbool.h>
#include "libvig/verified/boilerplate-util.h"

#include <stdint.h>

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 3
#define SKETCH_SALTS_BANK_SIZE 4

extern const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE];

struct hash_input {
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct hash {
  uint32_t value;
};

struct sketch_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

unsigned hash_hash(void *obj);
bool hash_eq(void *a, void *b);
void hash_allocate(void *obj);
unsigned sketch_hash(void *input, uint32_t salt, uint32_t bucket_size);
int sketch_fetch(void *indexes, void *buckets, uint32_t sketch_capacity,
                 uint16_t threshold, void *data);

#define LOG_hash(obj, p)                                                       \
  ;                                                                            \
  p("{");                                                                      \
  p("value: %d", obj->value);                                                  \
  p("}");

#ifdef KLEE_VERIFICATION
#  include <klee/klee.h>
#  include "libvig/models/str-descr.h"
extern struct str_field_descr hash_input_descrs[2];
extern struct nested_field_descr hash_input_nests[0];

extern struct str_field_descr hash_descrs[1];
extern struct nested_field_descr hash_nests[0];

extern struct str_field_descr sketch_data_descrs[3];
extern struct nested_field_descr sketch_data_nests[0];
#endif // KLEE_VERIFICATION

#endif //_SKETCH_H_INCLUDED_
