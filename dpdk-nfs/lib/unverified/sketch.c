#include "sketch.h"

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include "lib/verified/boilerplate-util.h"
#include "lib/verified/map.h"
#include "lib/verified/vector.h"
#include "lib/verified/double-chain.h"

#include "lib/verified/vigor-time.h"

struct internal_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

struct Sketch {
  struct Map *clients;
  struct Vector *keys;
  struct Vector *buckets;
  struct DoubleChain *allocators[SKETCH_HASHES];

  uint32_t capacity;
  uint16_t threshold;

  map_key_hash *kh;
  struct internal_data internal;
};

struct hash {
  uint32_t value;
};

struct bucket {
  uint32_t value;
};

struct sketch_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

unsigned find_next_power_of_2_bigger_than(uint32_t d) {
  assert(d <= 0x80000000);
  unsigned n = 1;

  while (n < d) {
    n *= 2;
  }

  return n;
}

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
  struct hash *id = (struct hash *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

void bucket_allocate(void *obj) { (uintptr_t) obj; }

int sketch_allocate(map_key_hash *kh, uint32_t capacity, uint16_t threshold,
                    struct Sketch **sketch_out) {
  assert(SKETCH_HASHES <= SKETCH_SALTS_BANK_SIZE);

  struct Sketch *sketch_alloc = (struct Sketch *)malloc(sizeof(struct Sketch));
  if (sketch_alloc == NULL) {
    return 0;
  }

  (*sketch_out) = sketch_alloc;

  (*sketch_out)->capacity = capacity;
  (*sketch_out)->threshold = threshold;
  (*sketch_out)->kh = kh;

  unsigned total_sketch_capacity =
      find_next_power_of_2_bigger_than(capacity * SKETCH_HASHES);

  (*sketch_out)->clients = NULL;
  if (map_allocate(hash_eq, hash_hash, total_sketch_capacity,
                   &((*sketch_out)->clients)) == 0) {
    return 0;
  }

  (*sketch_out)->keys = NULL;
  if (vector_allocate(sizeof(struct hash), total_sketch_capacity, hash_allocate,
                      &((*sketch_out)->keys)) == 0) {
    return 0;
  }

  (*sketch_out)->buckets = NULL;
  if (vector_allocate(sizeof(struct bucket), total_sketch_capacity,
                      bucket_allocate, &((*sketch_out)->buckets)) == 0) {
    return 0;
  }

  for (int i = 0; i < SKETCH_HASHES; i++) {
    (*sketch_out)->allocators[i] = NULL;
    if (dchain_allocate(capacity, &((*sketch_out)->allocators[i])) == 0) {
      return 0;
    }
  }

  return 1;
}

void sketch_compute_hashes(struct Sketch *sketch, void *key) {
  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal.buckets_indexes[i] = -1;
    sketch->internal.present[i] = 0;
    sketch->internal.hashes[i] = 0;

    sketch->internal.hashes[i] =
        __builtin_ia32_crc32si(sketch->internal.hashes[i], SKETCH_SALTS[i]);
    sketch->internal.hashes[i] =
        __builtin_ia32_crc32si(sketch->internal.hashes[i], sketch->kh(key));
    sketch->internal.hashes[i] %= sketch->capacity;
  }
}

void sketch_refresh(struct Sketch *sketch, vigor_time_t now) {
  for (int i = 0; i < SKETCH_HASHES; i++) {
    map_get(sketch->clients, &sketch->internal.hashes[i],
            &sketch->internal.buckets_indexes[i]);
    dchain_rejuvenate_index(sketch->allocators[i],
                            sketch->internal.buckets_indexes[i], now);
  }
}

int sketch_fetch(struct Sketch *sketch) {
  int bucket_min_set = false;
  uint32_t *buckets_values[SKETCH_HASHES];
  uint32_t bucket_min = 0;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal.present[i] =
        map_get(sketch->clients, &sketch->internal.hashes[i],
                &sketch->internal.buckets_indexes[i]);

    if (!sketch->internal.present[i]) {
      continue;
    }

    int offseted = sketch->internal.buckets_indexes[i] + sketch->capacity * i;
    vector_borrow(sketch->buckets, offseted, (void **)&buckets_values[i]);

    if (!bucket_min_set || bucket_min > *buckets_values[i]) {
      bucket_min = *buckets_values[i];
      bucket_min_set = true;
    }

    vector_return(sketch->buckets, offseted, buckets_values[i]);
  }

  return bucket_min_set && bucket_min > sketch->threshold;
}

int sketch_touch_buckets(struct Sketch *sketch, vigor_time_t now) {
  for (int i = 0; i < SKETCH_HASHES; i++) {
    int bucket_index = -1;
    int present =
        map_get(sketch->clients, &sketch->internal.hashes[i], &bucket_index);

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

      (*saved_hash) = sketch->internal.hashes[i];
      (*saved_bucket) = 0;
      map_put(sketch->clients, saved_hash, bucket_index);

      vector_return(sketch->keys, offseted, saved_hash);
      vector_return(sketch->buckets, offseted, saved_bucket);
    } else {
      dchain_rejuvenate_index(sketch->allocators[i], bucket_index, now);
      uint32_t *bucket;
      int offseted = bucket_index + sketch->capacity * i;
      vector_borrow(sketch->buckets, offseted, (void **)&bucket);
      (*bucket)++;
      vector_return(sketch->buckets, offseted, bucket);
    }
  }

  return true;
}

void sketch_expire(struct Sketch *sketch, vigor_time_t time) {
  int offset = 0;
  int index = -1;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    offset = i * sketch->capacity;

    while (dchain_expire_one_index(sketch->allocators[i], &index, time)) {
      void *key;
      vector_borrow(sketch->keys, index + offset, &key);
      map_erase(sketch->clients, key, &key);
      vector_return(sketch->keys, index + offset, key);
    }
  }
}