#include "sketch.h"

#include <stdint.h>

const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE] = {
  0xec99b144, 0x18a3b351, 0x4a030346, 0x3122358b,
  0x444db70b, 0x3a7762cc, 0xed3076f5, 0x5ef8e5f7
};

bool hash_eq(void *a, void *b) {
  struct hash *id1 = (struct hash *)a;
  struct hash *id2 = (struct hash *)b;

  return (id1->value == id2->value);
}

void hash_allocate(void *obj) {
  struct hash *id = (struct hash *)obj;
  id->value = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr hash_descrs[] = {
  { offsetof(struct hash, value), sizeof(uint32_t), 0, "value" },
};
struct nested_field_descr hash_nests[] = {};

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

struct str_field_descr sketch_descrs[7] = {
  { offsetof(struct Sketch, clients), sizeof(struct Map *), 0, "clients" },
  { offsetof(struct Sketch, keys), sizeof(struct Vector *), 0, "keys" },
  { offsetof(struct Sketch, buckets), sizeof(struct Vector *), 0, "buckets" },
  { offsetof(struct Sketch, allocators), sizeof(struct DoubleChain *),
    SKETCH_HASHES,                       "allocators" },
  { offsetof(struct Sketch, capacity), sizeof(uint32_t), 0, "capacity" },
  { offsetof(struct Sketch, bucket_size), sizeof(uint32_t), 0, "bucket_size" },
  { offsetof(struct Sketch, threshold), sizeof(uint16_t), 0, "threshold" },
};

struct nested_field_descr sketch_nests[0];

struct str_field_descr sketch_key_descrs[] = {
  { offsetof(struct sketch_key, src_ip), sizeof(uint32_t), 0, "src_ip" },
  { offsetof(struct sketch_key, dst_ip), sizeof(uint32_t), 0, "dst_ip" },
};
struct nested_field_descr sketch_key_nests[] = {};

struct str_field_descr sketch_data_descrs[3] =
    { { offsetof(struct sketch_data, hashes), sizeof(unsigned),
        SKETCH_HASHES,                        "hashes" },
      { offsetof(struct sketch_data, present), sizeof(int),
        SKETCH_HASHES,                         "present" },
      { offsetof(struct sketch_data, buckets_indexes), sizeof(int),
        SKETCH_HASHES,                                 "buckets_indexes" }, };

struct nested_field_descr sketch_data_nests[0];

void sketch_compute_hashes(void *obj, void *k, void *out) {
  klee_trace_param_tagged_ptr(obj, sizeof(struct Sketch), "sketch", "sketch",
                              TD_BOTH);
  for (int i = 0; i < sizeof(sketch_descrs) / sizeof(sketch_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, sketch_descrs[i].offset, sketch_descrs[i].width,
        sketch_descrs[i].count, sketch_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_nests) / sizeof(sketch_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, sketch_nests[i].base_offset, sketch_nests[i].offset,
        sketch_nests[i].width, sketch_nests[i].count, sketch_nests[i].name,
        TD_BOTH);
  }

  klee_trace_param_tagged_ptr(k, sizeof(struct sketch_key), "key", "sketch_key",
                              TD_BOTH);
  for (int i = 0; i < sizeof(sketch_key_descrs) / sizeof(sketch_key_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        k, sketch_key_descrs[i].offset, sketch_key_descrs[i].width,
        sketch_key_descrs[i].count, sketch_key_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_key_nests) / sizeof(sketch_key_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        k, sketch_key_nests[i].base_offset, sketch_key_nests[i].offset,
        sketch_key_nests[i].width, sketch_key_nests[i].count,
        sketch_key_nests[i].name, TD_BOTH);
  }

  klee_trace_param_tagged_ptr(out, sizeof(struct sketch_data), "out", "data",
                              TD_BOTH);
  for (int i = 0;
       i < sizeof(sketch_data_descrs) / sizeof(sketch_data_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        out, sketch_data_descrs[i].offset, sketch_data_descrs[i].width,
        sketch_data_descrs[i].count, sketch_data_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_data_nests) / sizeof(sketch_data_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        out, sketch_data_nests[i].base_offset, sketch_data_nests[i].offset,
        sketch_data_nests[i].width, sketch_data_nests[i].count,
        sketch_data_nests[i].name, TD_BOTH);
  }
}

void sketch_refresh(void *obj, void *out, vigor_time_t now) {
  klee_trace_param_tagged_ptr(obj, sizeof(struct Sketch), "sketch", "sketch",
                              TD_BOTH);
  for (int i = 0; i < sizeof(sketch_descrs) / sizeof(sketch_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, sketch_descrs[i].offset, sketch_descrs[i].width,
        sketch_descrs[i].count, sketch_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_nests) / sizeof(sketch_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, sketch_nests[i].base_offset, sketch_nests[i].offset,
        sketch_nests[i].width, sketch_nests[i].count, sketch_nests[i].name,
        TD_BOTH);
  }

  klee_trace_param_tagged_ptr(out, sizeof(struct sketch_data), "out", "data",
                              TD_BOTH);
  for (int i = 0;
       i < sizeof(sketch_data_descrs) / sizeof(sketch_data_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        out, sketch_data_descrs[i].offset, sketch_data_descrs[i].width,
        sketch_data_descrs[i].count, sketch_data_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_data_nests) / sizeof(sketch_data_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        out, sketch_data_nests[i].base_offset, sketch_data_nests[i].offset,
        sketch_data_nests[i].width, sketch_data_nests[i].count,
        sketch_data_nests[i].name, TD_BOTH);
  }

  klee_trace_param_u64(now, "now");
}

int sketch_fetch(void *obj, void *out) {
  klee_trace_ret();

  klee_trace_param_tagged_ptr(obj, sizeof(struct Sketch), "sketch", "sketch",
                              TD_BOTH);
  for (int i = 0; i < sizeof(sketch_descrs) / sizeof(sketch_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, sketch_descrs[i].offset, sketch_descrs[i].width,
        sketch_descrs[i].count, sketch_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_nests) / sizeof(sketch_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, sketch_nests[i].base_offset, sketch_nests[i].offset,
        sketch_nests[i].width, sketch_nests[i].count, sketch_nests[i].name,
        TD_BOTH);
  }

  klee_trace_param_tagged_ptr(out, sizeof(struct sketch_data), "out", "data",
                              TD_BOTH);
  for (int i = 0;
       i < sizeof(sketch_data_descrs) / sizeof(sketch_data_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        out, sketch_data_descrs[i].offset, sketch_data_descrs[i].width,
        sketch_data_descrs[i].count, sketch_data_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_data_nests) / sizeof(sketch_data_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        out, sketch_data_nests[i].base_offset, sketch_data_nests[i].offset,
        sketch_data_nests[i].width, sketch_data_nests[i].count,
        sketch_data_nests[i].name, TD_BOTH);
  }

  return klee_int("overflow");
}

int sketch_touch_buckets(void *obj, void *out, vigor_time_t now) {
  klee_trace_ret();

  klee_trace_param_tagged_ptr(obj, sizeof(struct Sketch), "sketch", "sketch",
                              TD_BOTH);
  for (int i = 0; i < sizeof(sketch_descrs) / sizeof(sketch_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, sketch_descrs[i].offset, sketch_descrs[i].width,
        sketch_descrs[i].count, sketch_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_nests) / sizeof(sketch_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, sketch_nests[i].base_offset, sketch_nests[i].offset,
        sketch_nests[i].width, sketch_nests[i].count, sketch_nests[i].name,
        TD_BOTH);
  }

  klee_trace_param_tagged_ptr(out, sizeof(struct sketch_data), "out", "data",
                              TD_BOTH);
  for (int i = 0;
       i < sizeof(sketch_data_descrs) / sizeof(sketch_data_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        out, sketch_data_descrs[i].offset, sketch_data_descrs[i].width,
        sketch_data_descrs[i].count, sketch_data_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_data_nests) / sizeof(sketch_data_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        out, sketch_data_nests[i].base_offset, sketch_data_nests[i].offset,
        sketch_data_nests[i].width, sketch_data_nests[i].count,
        sketch_data_nests[i].name, TD_BOTH);
  }

  klee_trace_param_u64(now, "now");

  return klee_int("success");
}

#else // KLEE_VERIFICATION

unsigned hash_hash(void *obj) {
  struct hash *id = (struct hash *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

void sketch_compute_hashes(void *obj, void *k, void *out) {
  struct Sketch *sketch = (struct Sketch *)obj;
  struct sketch_key *key = (struct sketch_key *)k;
  struct sketch_data *data = (struct sketch_data *)out;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    data->buckets_indexes[i] = -1;
    data->present[i] = 0;
    data->hashes[i] = 0;

    data->hashes[i] = __builtin_ia32_crc32si(data->hashes[i], SKETCH_SALTS[i]);
    data->hashes[i] = __builtin_ia32_crc32si(data->hashes[i], key->src_ip);
    data->hashes[i] = __builtin_ia32_crc32si(data->hashes[i], key->dst_ip);
    data->hashes[i] %= sketch->bucket_size;
  }
}

void sketch_refresh(void *obj, void *out, vigor_time_t now) {
  struct Sketch *sketch = (struct Sketch *)obj;
  struct sketch_data *data = (struct sketch_data *)out;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    map_get(sketch->clients, &data->hashes[i], &data->buckets_indexes[i]);
    dchain_rejuvenate_index(sketch->allocators[i], data->buckets_indexes[i],
                            now);
  }
}

int sketch_fetch(void *obj, void *out) {
  struct Sketch *sketch = (struct Sketch *)obj;
  struct sketch_data *data = (struct sketch_data *)out;

  int bucket_min_set = false;
  uint32_t *buckets_values[SKETCH_HASHES];
  uint32_t bucket_min = 0;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    data->present[i] =
        map_get(sketch->clients, &data->hashes[i], &data->buckets_indexes[i]);

    if (!data->present[i]) {
      continue;
    }

    int offseted = data->buckets_indexes[i] + sketch->capacity * i;
    vector_borrow(sketch->buckets, offseted, (void **)&buckets_values[i]);

    if (!bucket_min_set || bucket_min > *buckets_values[i]) {
      bucket_min = *buckets_values[i];
      bucket_min_set = true;
    }

    vector_return(sketch->buckets, offseted, buckets_values[i]);
  }

  return bucket_min_set && bucket_min > sketch->threshold;
}

int sketch_touch_buckets(void *obj, void *out, vigor_time_t now) {
  struct Sketch *sketch = (struct Sketch *)obj;
  struct sketch_data *data = (struct sketch_data *)out;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    int bucket_index = -1;
    int present = map_get(sketch->clients, &data->hashes[i], &bucket_index);

    if (!present) {
      int allocated_client =
          dchain_allocate_new_index(sketch->allocators[i], &bucket_index, now);

      if (!allocated_client) {
        // Sketch size limit reached.
        return false;
      }

      int offseted = bucket_index + sketch->capacity * i;

      uint32_t *saved_hash = 0;
      uint32_t *saved_bucket = 0;

      vector_borrow(sketch->keys, offseted, (void **)&saved_hash);
      vector_borrow(sketch->buckets, offseted, (void **)&saved_bucket);

      (*saved_hash) = data->hashes[i];
      (*saved_bucket) = 0;
      map_put(sketch->clients, saved_hash, bucket_index);

      vector_return(sketch->keys, offseted, saved_hash);
      vector_return(sketch->buckets, offseted, saved_bucket);

      return true;
    } else {
      dchain_rejuvenate_index(sketch->allocators[i], bucket_index, now);
      uint32_t *bucket;
      int offseted = bucket_index + sketch->capacity * i;
      vector_borrow(sketch->buckets, offseted, (void **)&bucket);
      (*bucket)++;
      vector_return(sketch->buckets, offseted, bucket);
      return true;
    }
  }
}

#endif // KLEE_VERIFICATION
