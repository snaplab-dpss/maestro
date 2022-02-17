#include <stdlib.h>
#include <string.h>
#include <klee/klee.h>
#include "libvig/unverified/sketch.h"
#include "sketch-control.h"

#include "../verified/double-chain-control.h"
#include "../verified/map-control.h"
#include "../verified/vector-control.h"

static int calculate_str_size(struct str_field_descr *descr, int len) {
  int rez = 0;
  int sum = 0;
  for (int i = 0; i < len; ++i) {
    sum += descr[i].width;
    if (descr[i].offset + descr[i].width > rez)
      rez = descr[i].offset + descr[i].width;
  }
  klee_assert(rez == sum);
  return rez;
}

unsigned find_next_power_of_2_bigger_than(uint32_t d) {
  assert(d <= 0x80000000);
  unsigned n = 1;

  while (n < d) {
    n *= 2;
  }

  return n;
}

struct str_field_descr hash_descrs[] = {
    {offsetof(struct hash, value), sizeof(uint32_t), 0, "value"}, };
struct nested_field_descr hash_nests[] = {};

bool hash_eq(void *a, void *b) {
  struct hash *id1 = (struct hash *)a;
  struct hash *id2 = (struct hash *)b;

  return (id1->value == id2->value);
}

void hash_allocate(void *obj) {
  struct hash *id = (struct hash *)obj;
  id->value = 0;
}

unsigned hash_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct hash), "obj", "hash", TD_BOTH);
  for (int i = 0; i < sizeof(hash_descrs) / sizeof(hash_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, hash_descrs[i].offset, hash_descrs[i].width, hash_descrs[i].count,
        hash_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(hash_nests) / sizeof(hash_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, hash_nests[i].base_offset, hash_nests[i].offset,
        hash_nests[i].width, hash_nests[i].count, hash_nests[i].name, TD_BOTH);
  }
  return klee_int("hash_hash");
}

struct str_field_descr bucket_descrs[] = {
    {offsetof(struct bucket, value), sizeof(uint32_t), 0, "value"}, };
struct nested_field_descr bucket_nests[] = {};

bool bucket_eq(void *a, void *b) {
  struct bucket *id1 = (struct bucket *)a;
  struct bucket *id2 = (struct bucket *)b;

  return (id1->value == id2->value);
}

void bucket_allocate(void *obj) { (uintptr_t) obj; }

unsigned bucket_hash(void *obj) {
  struct bucket *id = (struct bucket *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

void sketch_set_layout(struct Sketch *sketch,
                       struct str_field_descr *key_fields, int key_fields_count,
                       struct nested_field_descr *key_nests,
                       int nested_key_fields_count, char *key_type) {
  // Do not trace. This function is an internal knob of the model.
  klee_assert(key_fields_count < PREALLOC_SIZE);
  klee_assert(nested_key_fields_count < PREALLOC_SIZE);
  memcpy(sketch->key_fields, key_fields,
         sizeof(struct str_field_descr) * key_fields_count);
  if (0 < nested_key_fields_count) {
    memcpy(sketch->key_nests, key_nests,
           sizeof(struct nested_field_descr) * nested_key_fields_count);
  }
  sketch->key_field_count = key_fields_count;
  sketch->nested_key_field_count = nested_key_fields_count;
  sketch->key_size = calculate_str_size(key_fields, key_fields_count);
  klee_assert(sketch->key_size < PREALLOC_SIZE);
  sketch->has_layout = 1;
  sketch->key_type = key_type;
}

void sketch_set_entry_condition(struct Sketch *sketch,
                                sketch_entry_condition *cond, void *state) {}

void sketch_reset(struct Sketch *sketch) {}

int sketch_allocate(map_key_hash *khash, uint32_t capacity, uint16_t threshold,
                    struct Sketch **sketch_out) {
  klee_trace_ret();

  klee_trace_param_fptr(khash, "khash");
  klee_trace_param_u32(capacity, "capacity");
  klee_trace_param_u16(threshold, "threshold");
  klee_trace_param_ptr(sketch_out, sizeof(struct Sketch *), "sketch_out");

  klee_assert(SKETCH_HASHES <= SKETCH_SALTS_BANK_SIZE);

  int allocation_succeeded = klee_int("sketch_allocation_succeeded");

  if (allocation_succeeded) {
    *sketch_out = malloc(sizeof(struct Sketch));
    klee_make_symbolic((*sketch_out), sizeof(struct Sketch), "sketch");
    klee_assert((*sketch_out) != NULL);
    return 1;
  }

  return 0;
}

void sketch_compute_hashes(struct Sketch *sketch, void *k) {
  klee_trace_param_i32((uint32_t)sketch, "sketch");
  klee_trace_param_tagged_ptr(k, sketch->key_size, "key", sketch->key_type,
                              TD_BOTH);
}

void sketch_refresh(struct Sketch *sketch, vigor_time_t now) {
  klee_trace_param_i32((uint32_t)sketch, "sketch");
  klee_trace_param_u64(now, "time");
}

int sketch_fetch(struct Sketch *sketch) {
  klee_trace_ret();
  klee_trace_param_i32((uint32_t)sketch, "sketch");
  return klee_int("overflow");
}

int sketch_touch_buckets(struct Sketch *sketch, vigor_time_t now) {
  klee_trace_ret();
  klee_trace_param_i32((uint32_t)sketch, "sketch");
  klee_trace_param_u64(now, "time");
  return klee_int("success");
}

void sketch_expire(struct Sketch *sketch, vigor_time_t time) {
  klee_trace_param_u64((uint64_t)sketch, "sketch");
  klee_trace_param_i64(time, "time");

  for (int i = 0; i < SKETCH_HASHES; i++) {
    int nfreed = klee_int("number_of_freed_flows");
    klee_assume(0 <= nfreed);
    // dchain_make_space(sketch->allocators[i], nfreed);
  }
}
