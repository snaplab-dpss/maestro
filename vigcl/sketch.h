#ifndef _SKETCH_H_INCLUDED_
#define _SKETCH_H_INCLUDED_

#include <stdbool.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/double-chain.h"
#include "libvig/verified/vigor-time.h"

#include <stdint.h>

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 4
#define SKETCH_SALTS_BANK_SIZE 8

extern const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE];

struct Sketch {
  struct Map *clients;
  struct Vector *keys;
  struct Vector *buckets;
  struct DoubleChain *allocators[SKETCH_HASHES];

  uint32_t capacity;
  uint32_t bucket_size;
  uint16_t threshold;
};

struct sketch_key {
  uint32_t src_ip;
  uint32_t dst_ip;
};

struct sketch_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

struct hash {
  uint32_t value;
};

unsigned hash_hash(void *obj);
bool hash_eq(void *a, void *b);
void hash_allocate(void *obj);
void sketch_compute_hashes(void *obj, void *k, void *out);
void sketch_refresh(void *obj, void *out, vigor_time_t now);
int sketch_fetch(void *obj, void *out);
int sketch_touch_buckets(void *obj, void *out, vigor_time_t now);

#define LOG_hash(obj, p)                                                       \
  ;                                                                            \
  p("{");                                                                      \
  p("value: %d", obj->value);                                                  \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "libvig/models/str-descr.h"
extern struct str_field_descr sketch_descrs[7];
extern struct nested_field_descr sketch_nests[0];

extern struct str_field_descr sketch_key_descrs[2];
extern struct nested_field_descr sketch_key_nests[0];

extern struct str_field_descr sketch_data_descrs[3];
extern struct nested_field_descr sketch_data_nests[0];

extern struct str_field_descr hash_descrs[1];
extern struct nested_field_descr hash_nests[0];
#endif // KLEE_VERIFICATION

#endif //_SKETCH_H_INCLUDED_
