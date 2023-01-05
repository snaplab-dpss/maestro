#ifndef _SKETCH_STUB_CONTROL_H_INCLUDED_
#define _SKETCH_STUB_CONTROL_H_INCLUDED_

#include "lib/unverified/sketch.h"
#include "lib/models/str-descr.h"
#include "../verified/map-control.h"

#define PREALLOC_SIZE (256)

typedef map_entry_condition sketch_entry_condition;

extern struct str_field_descr hash_fields[1];
extern struct nested_field_descr hash_nests[0];

extern struct str_field_descr bucket_fields[1];
extern struct nested_field_descr bucket_nests[0];

struct Sketch {
  struct Map *clients;
  struct Vector *keys;
  struct Vector *buckets;
  struct DoubleChain *allocators[SKETCH_HASHES];

  struct str_field_descr key_fields[PREALLOC_SIZE];
  struct nested_field_descr key_nests[PREALLOC_SIZE];
  int key_field_count;
  int nested_key_field_count;
  int has_layout;
  int key_size;
  char *key_type;
};

struct hash {
  uint32_t value;
};

struct bucket {
  uint32_t value;
};

void sketch_set_layout(struct Sketch *sketch,
                       struct str_field_descr *key_fields, int key_fields_count,
                       struct nested_field_descr *key_nests,
                       int nested_key_fields_count, char *key_type);

void sketch_set_entry_condition(struct Sketch *sketch,
                                sketch_entry_condition *cond, void *state);

void sketch_reset(struct Sketch *sketch);

#endif