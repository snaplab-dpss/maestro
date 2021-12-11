#include "sketch.h"

#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/double-chain,h"
#include "libvig/verified/vigor-time.h"

#include <stdint.h>

const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE] = { 0xec99b144, 0x18a3b351,
                                                        0x4a030346,
                                                        0x3122358b };

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

struct str_field_descr hash_input_descrs[] = {
  { offsetof(struct hash_input, src_ip), sizeof(uint32_t), 0, "src_ip" },
  { offsetof(struct hash_input, dst_ip), sizeof(uint32_t), 0, "dst_ip" },
};
struct nested_field_descr hash_input_nests[] = {};

unsigned sketch_hash(void *input, uint32_t salt, uint32_t bucket_size) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(input, sizeof(struct hash_input), "input",
                              "hash_input", TD_BOTH);
  for (int i = 0; i < sizeof(hash_input_descrs) / sizeof(hash_input_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        input, hash_input_descrs[i].offset, hash_input_descrs[i].width,
        hash_input_descrs[i].count, hash_input_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(hash_input_nests) / sizeof(hash_input_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        input, hash_input_nests[i].base_offset, hash_input_nests[i].offset,
        hash_input_nests[i].width, hash_input_nests[i].count,
        hash_input_nests[i].name, TD_BOTH);
  }

  klee_trace_param_u32(salt, "salt");
  klee_trace_param_u32(bucket_size, "bucket_size");

  return klee_int("sketch_hash");
}

struct str_field_descr sketch_data_descrs[3] = {
  { offsetof(struct sketch_data, hashes), sizeof(unsigned), SKETCH_HASHES,
    "hashes" },
  { offsetof(struct sketch_data, present), sizeof(int), SKETCH_HASHES,
    "present" },
  { offsetof(struct sketch_data, buckets_indexes), sizeof(int), SKETCH_HASHES,
    "buckets_indexes" },
};

struct nested_field_descr sketch_data_nests[0];

int sketch_fetch(void *indexes, void *buckets, uint32_t sketch_capacity,
                 uint16_t threshold, void *data) {
  klee_trace_ret();
  klee_trace_param_u64((uint64_t)indexes, "indexes");
  klee_trace_param_u64((uint64_t)buckets, "buckets");

  klee_trace_param_u32(sketch_capacity, "sketch_capacity");
  klee_trace_param_u16(threshold, "threshold");

  klee_trace_param_tagged_ptr(data, sizeof(struct sketch_data), "data",
                              "sketch_data", TD_BOTH);
  for (int i = 0;
       i < sizeof(sketch_data_descrs) / sizeof(sketch_data_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        data, sketch_data_descrs[i].offset, sketch_data_descrs[i].width,
        sketch_data_descrs[i].count, sketch_data_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(sketch_data_nests) / sizeof(sketch_data_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        data, sketch_data_nests[i].base_offset, sketch_data_nests[i].offset,
        sketch_data_nests[i].width, sketch_data_nests[i].count,
        sketch_data_nests[i].name, TD_BOTH);
  }

  return klee_int("overflow");
}

#else // KLEE_VERIFICATION

unsigned hash_hash(void *obj) {
  struct hash *id = (struct hash *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

unsigned sketch_hash(void *input, uint32_t salt, uint32_t bucket_size) {
  struct hash_input *hash_input = (struct hash_input *)input;

  unsigned sketch_hash = 0;
  sketch_hash = __builtin_ia32_crc32si(sketch_hash, salt);
  sketch_hash = __builtin_ia32_crc32si(sketch_hash, hash_input->src_ip);
  sketch_hash = __builtin_ia32_crc32si(sketch_hash, hash_input->dst_ip);
  sketch_hash %= bucket_size;

  return sketch_hash;
}

int sketch_fetch(void *indexes, void *buckets, uint32_t sketch_capacity,
                 uint16_t threshold, void *data) {
  struct Map *indexes_cast = (struct Map *)indexes;
  struct Vector *buckets_cast = (struct Vector *)buckets;
  struct sketch_data *sketch_data = (struct sketch_data *)data;

  int bucket_min_set = false;
  uint32_t *buckets_values[SKETCH_HASHES];
  uint32_t bucket_min = 0;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch_data->present[i] = map_get(indexes_cast, &sketch_data->hashes[i],
                                      &sketch_data->buckets_indexes[i]);

    if (!sketch_data->present[i]) {
      continue;
    }

    int offseted = sketch_data->buckets_indexes[i] + sketch_capacity * i;
    vector_borrow(buckets_cast, offseted, (void **)&buckets_values[i]);

    if (!bucket_min_set || bucket_min > *buckets_values[i]) {
      bucket_min = *buckets_values[i];
      bucket_min_set = true;
    }

    vector_return(buckets_cast, offseted, buckets_values[i]);
  }

  return bucket_min_set && bucket_min > threshold;
}

int sketch_touch_buckets(void *indexes, void *buckets, void *allocator,
                         void *data, vigor_time_t now) {
  struct Map *indexes_cast = (struct Map *)indexes;
  struct Vector *buckets_cast = (struct Vector *)buckets;
  struct Vector *buckets_cast = (struct DoubleChain *)buckets;
  struct sketch_data *sketch_data = (struct sketch_data *)data;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    int bucket_index = -1;
    int present = map_get(indexes, &sketch_data->hashes[i], &bucket_index);

    if (!present) {
      int allocated_client = dchain_allocate_new_index(
          state->client_allocator[sketch_iteration], &bucket_index, now);

      if (!allocated_client) {
        // Sketch size limit reached.
        return false;
      }

      int offseted = bucket_index + state->sketch_capacity * sketch_iteration;

      uint32_t *saved_hash = NULL;
      uint32_t *saved_bucket = NULL;

      vector_borrow(state->clients_keys, offseted, (void **)&saved_hash);
      vector_borrow(state->clients_buckets, offseted, (void **)&saved_bucket);

      (*saved_hash) = sketch_hash;
      (*saved_bucket) = 0;
      map_put(state->clients, saved_hash, bucket_index);

      vector_return(state->clients_keys, offseted, saved_hash);
      vector_return(state->clients_buckets, offseted, saved_bucket);

      return true;
    } else {
      dchain_rejuvenate_index(state->client_allocator[sketch_iteration],
                              bucket_index, now);
      uint32_t *bucket;
      int offseted = bucket_index + state->sketch_capacity * sketch_iteration;
      vector_borrow(state->clients_buckets, offseted, (void **)&bucket);
      (*bucket)++;
      vector_return(state->clients_buckets, offseted, bucket);
      return true;
    }
  }
}

#endif // KLEE_VERIFICATION
