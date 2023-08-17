#include <linux/limits.h>
#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>


/**********************************************
 *
 *                   LIBVIG
 *
 **********************************************/

#define AND &&
#define vigor_time_t int64_t

vigor_time_t current_time(void) {
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return tp.tv_sec * 1000000000ul + tp.tv_nsec;
}

typedef unsigned map_key_hash(void *k1);
typedef bool map_keys_equality(void *k1, void *k2);

struct Map {
  int *busybits;
  void **keyps;
  unsigned *khs;
  int *chns;
  int *vals;
  unsigned capacity;
  unsigned size;
  map_keys_equality *keys_eq;
  map_key_hash *khash;
};

static unsigned loop(unsigned k, unsigned capacity) {
  return k & (capacity - 1);
}

static int find_key(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                    void *keyp, map_keys_equality *eq, unsigned key_hash,
                    unsigned capacity) {
  unsigned start = loop(key_hash, capacity);
  unsigned i = 0;
  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    unsigned kh = k_hashes[index];
    int chn = chns[index];
    void *kp = keyps[index];
    if (bb != 0 && kh == key_hash) {
      if (eq(kp, keyp)) {
        return (int)index;
      }
    } else {
      if (chn == 0) {
        return -1;
      }
    }
  }

  return -1;
}

static unsigned find_key_remove_chain(int *busybits, void **keyps,
                                      unsigned *k_hashes, int *chns, void *keyp,
                                      map_keys_equality *eq, unsigned key_hash,
                                      unsigned capacity, void **keyp_out) {
  unsigned i = 0;
  unsigned start = loop(key_hash, capacity);

  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    unsigned kh = k_hashes[index];
    int chn = chns[index];
    void *kp = keyps[index];
    if (bb != 0 && kh == key_hash) {
      if (eq(kp, keyp)) {
        busybits[index] = 0;
        *keyp_out = keyps[index];
        return index;
      }
    }

    chns[index] = chn - 1;
  }

  return -1;
}

static unsigned find_empty(int *busybits, int *chns, unsigned start,
                           unsigned capacity) {
  unsigned i = 0;
  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);

    int bb = busybits[index];
    if (0 == bb) {
      return index;
    }
    int chn = chns[index];

    chns[index] = chn + 1;
  }

  return -1;
}

void map_impl_init(int *busybits, map_keys_equality *eq, void **keyps,
                   unsigned *khs, int *chns, int *vals, unsigned capacity) {
  (uintptr_t) eq;
  (uintptr_t) keyps;
  (uintptr_t) khs;
  (uintptr_t) vals;

  unsigned i = 0;
  for (; i < capacity; ++i) {
    busybits[i] = 0;
    chns[i] = 0;
  }
}

int map_impl_get(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                 int *values, void *keyp, map_keys_equality *eq, unsigned hash,
                 int *value, unsigned capacity) {
  int index =
      find_key(busybits, keyps, k_hashes, chns, keyp, eq, hash, capacity);

  if (-1 == index) {
    return 0;
  }

  *value = values[index];

  return 1;
}

void map_impl_put(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                  int *values, void *keyp, unsigned hash, int value,
                  unsigned capacity) {
  unsigned start = loop(hash, capacity);
  unsigned index = find_empty(busybits, chns, start, capacity);

  busybits[index] = 1;
  keyps[index] = keyp;
  k_hashes[index] = hash;
  values[index] = value;
}

void map_impl_erase(int *busybits, void **keyps, unsigned *k_hashes, int *chns,
                    void *keyp, map_keys_equality *eq, unsigned hash,
                    unsigned capacity, void **keyp_out) {
  find_key_remove_chain(busybits, keyps, k_hashes, chns, keyp, eq, hash,
                        capacity, keyp_out);
}

unsigned map_impl_size(int *busybits, unsigned capacity) {
  unsigned s = 0;
  unsigned i = 0;
  for (; i < capacity; ++i) {
    if (busybits[i] != 0) {
      ++s;
    }
  }

  return s;
}

int map_allocate(map_keys_equality *keq, map_key_hash *khash, unsigned capacity,
                 struct Map **map_out) {
  struct Map *old_map_val = *map_out;
  struct Map *map_alloc =
      (struct Map *)rte_malloc(NULL, sizeof(struct Map), 64);
  if (map_alloc == NULL)
    return 0;
  *map_out = (struct Map *)map_alloc;
  int *bbs_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (bbs_alloc == NULL) {
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->busybits = bbs_alloc;
  void **keyps_alloc =
      (void **)rte_malloc(NULL, sizeof(void *) * (int)capacity, 64);
  if (keyps_alloc == NULL) {
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->keyps = keyps_alloc;
  unsigned *khs_alloc =
      (unsigned *)rte_malloc(NULL, sizeof(unsigned) * (int)capacity, 64);
  if (khs_alloc == NULL) {
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->khs = khs_alloc;
  int *chns_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (chns_alloc == NULL) {
    rte_free(khs_alloc);
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->chns = chns_alloc;
  int *vals_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);

  if (vals_alloc == NULL) {
    rte_free(chns_alloc);
    rte_free(khs_alloc);
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }

  (*map_out)->vals = vals_alloc;
  (*map_out)->capacity = capacity;
  (*map_out)->size = 0;
  (*map_out)->keys_eq = keq;
  (*map_out)->khash = khash;

  map_impl_init((*map_out)->busybits, keq, (*map_out)->keyps, (*map_out)->khs,
                (*map_out)->chns, (*map_out)->vals, capacity);
  return 1;
}

int map_get(struct Map *map, void *key, int *value_out) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  return map_impl_get(map->busybits, map->keyps, map->khs, map->chns, map->vals,
                      key, map->keys_eq, hash, value_out, map->capacity);
}

void map_put(struct Map *map, void *key, int value) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  map_impl_put(map->busybits, map->keyps, map->khs, map->chns, map->vals, key,
               hash, value, map->capacity);
  ++map->size;
}

void map_erase(struct Map *map, void *key, void **trash) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  map_impl_erase(map->busybits, map->keyps, map->khs, map->chns, key,
                 map->keys_eq, hash, map->capacity, trash);

  --map->size;
}

unsigned map_size(struct Map *map) { return map->size; }

// Makes sure the allocator structur fits into memory, and particularly into
// 32 bit address space.
#define IRANG_LIMIT (1048576)

// kinda hacky, but makes the proof independent of vigor_time_t... sort of
#define malloc_block_time malloc_block_llongs
#define time_integer llong_integer
#define times llongs

#define DCHAIN_RESERVED (2)

struct dchain_cell {
  int prev;
  int next;
};

struct DoubleChain {
  struct dchain_cell *cells;
  vigor_time_t *timestamps;
};

enum DCHAIN_ENUM {
  ALLOC_LIST_HEAD = 0,
  FREE_LIST_HEAD = 1,
  INDEX_SHIFT = DCHAIN_RESERVED
};

void dchain_impl_init(struct dchain_cell *cells, int size) {
  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;
  al_head->prev = 0;
  al_head->next = 0;
  int i = INDEX_SHIFT;

  struct dchain_cell *fl_head = cells + FREE_LIST_HEAD;
  fl_head->next = i;
  fl_head->prev = fl_head->next;

  while (i < (size + INDEX_SHIFT - 1)) {
    struct dchain_cell *current = cells + i;
    current->next = i + 1;
    current->prev = current->next;

    ++i;
  }

  struct dchain_cell *last = cells + i;
  last->next = FREE_LIST_HEAD;
  last->prev = last->next;
}

int dchain_impl_allocate_new_index(struct dchain_cell *cells, int *index) {
  struct dchain_cell *fl_head = cells + FREE_LIST_HEAD;
  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;
  int allocated = fl_head->next;
  if (allocated == FREE_LIST_HEAD) {
    return 0;
  }

  struct dchain_cell *allocp = cells + allocated;
  // Extract the link from the "empty" chain.
  fl_head->next = allocp->next;
  fl_head->prev = fl_head->next;

  // Add the link to the "new"-end "alloc" chain.
  allocp->next = ALLOC_LIST_HEAD;
  allocp->prev = al_head->prev;

  struct dchain_cell *alloc_head_prevp = cells + al_head->prev;
  alloc_head_prevp->next = allocated;
  al_head->prev = allocated;

  *index = allocated - INDEX_SHIFT;

  return 1;
}

int dchain_impl_free_index(struct dchain_cell *cells, int index) {
  int freed = index + INDEX_SHIFT;

  struct dchain_cell *freedp = cells + freed;
  int freed_prev = freedp->prev;
  int freed_next = freedp->next;

  // The index is already free.
  if (freed_next == freed_prev) {
    if (freed_prev != ALLOC_LIST_HEAD) {
      return 0;
    }
  }

  struct dchain_cell *fr_head = cells + FREE_LIST_HEAD;
  struct dchain_cell *freed_prevp = cells + freed_prev;
  freed_prevp->next = freed_next;

  struct dchain_cell *freed_nextp = cells + freed_next;
  freed_nextp->prev = freed_prev;

  freedp->next = fr_head->next;
  freedp->prev = freedp->next;

  fr_head->next = freed;
  fr_head->prev = fr_head->next;

  return 1;
}

int dchain_impl_get_oldest_index(struct dchain_cell *cells, int *index) {
  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;

  // No allocated indexes.
  if (al_head->next == ALLOC_LIST_HEAD) {
    return 0;
  }

  *index = al_head->next - INDEX_SHIFT;

  return 1;
}

int dchain_impl_rejuvenate_index(struct dchain_cell *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_cell *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  if (lifted_next == lifted_prev) {
    if (lifted_next != ALLOC_LIST_HEAD) {
      return 0;
    } else {
      return 1;
    }
  }

  struct dchain_cell *lifted_prevp = cells + lifted_prev;
  lifted_prevp->next = lifted_next;

  struct dchain_cell *lifted_nextp = cells + lifted_next;
  lifted_nextp->prev = lifted_prev;

  struct dchain_cell *al_head = cells + ALLOC_LIST_HEAD;
  int al_head_prev = al_head->prev;

  liftedp->next = ALLOC_LIST_HEAD;
  liftedp->prev = al_head_prev;

  struct dchain_cell *al_head_prevp = cells + al_head_prev;
  al_head_prevp->next = lifted;

  al_head->prev = lifted;
  return 1;
}

int dchain_impl_is_index_allocated(struct dchain_cell *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_cell *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  int result;
  if (lifted_next == lifted_prev) {
    if (lifted_next != ALLOC_LIST_HEAD) {
      return 0;
    } else {
      return 1;
    }
  } else {
    return 1;
  }
}

int dchain_allocate(int index_range, struct DoubleChain **chain_out) {

  struct DoubleChain *old_chain_out = *chain_out;
  struct DoubleChain *chain_alloc =
      (struct DoubleChain *)rte_malloc(NULL, sizeof(struct DoubleChain), 64);
  if (chain_alloc == NULL)
    return 0;
  *chain_out = (struct DoubleChain *)chain_alloc;

  struct dchain_cell *cells_alloc = (struct dchain_cell *)rte_malloc(
      NULL, sizeof(struct dchain_cell) * (index_range + DCHAIN_RESERVED), 64);
  if (cells_alloc == NULL) {
    rte_free(chain_alloc);
    *chain_out = old_chain_out;
    return 0;
  }
  (*chain_out)->cells = cells_alloc;

  vigor_time_t *timestamps_alloc = (vigor_time_t *)rte_malloc(
      NULL, sizeof(vigor_time_t) * (index_range), 64);
  if (timestamps_alloc == NULL) {
    rte_free((void *)cells_alloc);
    rte_free(chain_alloc);
    *chain_out = old_chain_out;
    return 0;
  }
  (*chain_out)->timestamps = timestamps_alloc;

  dchain_impl_init((*chain_out)->cells, index_range);

  return 1;
}

int dchain_allocate_new_index(struct DoubleChain *chain, int *index_out,
                              vigor_time_t time) {
  int ret = dchain_impl_allocate_new_index(chain->cells, index_out);

  if (ret) {
    chain->timestamps[*index_out] = time;
  }

  return ret;
}

int dchain_rejuvenate_index(struct DoubleChain *chain, int index,
                            vigor_time_t time) {
  int ret = dchain_impl_rejuvenate_index(chain->cells, index);

  if (ret) {
    chain->timestamps[index] = time;
  }

  return ret;
}

int dchain_expire_one_index(struct DoubleChain *chain, int *index_out,
                            vigor_time_t time) {
  int has_ind = dchain_impl_get_oldest_index(chain->cells, index_out);

  if (has_ind) {
    if (chain->timestamps[*index_out] < time) {
      int rez = dchain_impl_free_index(chain->cells, *index_out);
      return rez;
    }
  }

  return 0;
}

int dchain_is_index_allocated(struct DoubleChain *chain, int index) {
  return dchain_impl_is_index_allocated(chain->cells, index);
}

int dchain_free_index(struct DoubleChain *chain, int index) {
  return dchain_impl_free_index(chain->cells, index);
}

#define VECTOR_CAPACITY_UPPER_LIMIT 140000

typedef void vector_init_elem(void *elem);

struct Vector {
  char *data;
  int elem_size;
  unsigned capacity;
};

int vector_allocate(int elem_size, unsigned capacity,
                    vector_init_elem *init_elem, struct Vector **vector_out) {
  struct Vector *old_vector_val = *vector_out;
  struct Vector *vector_alloc =
      (struct Vector *)rte_malloc(NULL, sizeof(struct Vector), 64);
  if (vector_alloc == 0)
    return 0;
  *vector_out = (struct Vector *)vector_alloc;

  char *data_alloc =
      (char *)rte_malloc(NULL, (uint32_t)elem_size * capacity, 64);
  if (data_alloc == 0) {
    rte_free(vector_alloc);
    *vector_out = old_vector_val;
    return 0;
  }
  (*vector_out)->data = data_alloc;
  (*vector_out)->elem_size = elem_size;
  (*vector_out)->capacity = capacity;

  for (unsigned i = 0; i < capacity; ++i) {
    init_elem((*vector_out)->data + elem_size * (int)i);
  }

  return 1;
}

void vector_borrow(struct Vector *vector, int index, void **val_out) {
  *val_out = vector->data + index * vector->elem_size;
}

void vector_return(struct Vector *vector, int index, void *value) {}

int expire_items_single_map(struct DoubleChain *chain, struct Vector *vector,
                            struct Map *map, vigor_time_t time) {
  int count = 0;
  int index = -1;

  while (dchain_expire_one_index(chain, &index, time)) {
    void *key;
    vector_borrow(vector, index, &key);
    map_erase(map, key, &key);
    vector_return(vector, index, key);

    ++count;
  }

  return count;
}

int expire_items_single_map_iteratively(struct Vector *vector, struct Map *map,
                                        int start, int n_elems) {
  assert(start >= 0);
  assert(n_elems >= 0);
  void *key;
  for (int i = start; i < n_elems; i++) {
    vector_borrow(vector, i, (void **)&key);
    map_erase(map, key, (void **)&key);
    vector_return(vector, i, key);
  }
}

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 4
#define SKETCH_SALTS_BANK_SIZE 64

struct internal_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
};

static const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE] = {
  0x9b78350f, 0x9bcf144c, 0x8ab29a3e, 0x34d48bf5, 0x78e47449, 0xd6e4af1d,
  0x32ed75e2, 0xb1eb5a08, 0x9cc7fbdf, 0x65b811ea, 0x41fd5ed9, 0x2e6a6782,
  0x3549661d, 0xbb211240, 0x78daa2ae, 0x8ce2d11f, 0x52911493, 0xc2497bd5,
  0x83c232dd, 0x3e413e9f, 0x8831d191, 0x6770ac67, 0xcd1c9141, 0xad35861a,
  0xb79cd83d, 0xce3ec91f, 0x360942d1, 0x905000fa, 0x28bb469a, 0xdb239a17,
  0x615cf3ae, 0xec9f7807, 0x271dcc3c, 0x47b98e44, 0x33ff4a71, 0x02a063f8,
  0xb051ebf2, 0x6f938d98, 0x2279abc3, 0xd55b01db, 0xaa99e301, 0x95d0587c,
  0xaee8684e, 0x24574971, 0x4b1e79a6, 0x4a646938, 0xa68d67f4, 0xb87839e6,
  0x8e3d388b, 0xed2af964, 0x541b83e3, 0xcb7fc8da, 0xe1140f8c, 0xe9724fd6,
  0x616a78fa, 0x610cd51c, 0x10f9173e, 0x8e180857, 0xa8f0b843, 0xd429a973,
  0xceee91e5, 0x1d4c6b18, 0x2a80e6df, 0x396f4d23,
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

/**********************************************
 *
 *                  RTE-IP
 *
 **********************************************/

uint32_t __raw_cksum(const void *buf, size_t len, uint32_t sum) {
  /* workaround gcc strict-aliasing warning */
  uintptr_t ptr = (uintptr_t)buf;
  typedef uint16_t __attribute__((__may_alias__)) u16_p;
  const u16_p *u16_buf = (const u16_p *)ptr;

  while (len >= (sizeof(*u16_buf) * 4)) {
    sum += u16_buf[0];
    sum += u16_buf[1];
    sum += u16_buf[2];
    sum += u16_buf[3];
    len -= sizeof(*u16_buf) * 4;
    u16_buf += 4;
  }
  while (len >= sizeof(*u16_buf)) {
    sum += *u16_buf;
    len -= sizeof(*u16_buf);
    u16_buf += 1;
  }

  /* if length is in odd bytes */
  if (len == 1) {
    uint16_t left = 0;
    *(uint8_t *)&left = *(const uint8_t *)u16_buf;
    sum += left;
  }

  return sum;
}

uint16_t __raw_cksum_reduce(uint32_t sum) {
  sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
  sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
  return (uint16_t)sum;
}

uint16_t raw_cksum(const void *buf, size_t len) {
  uint32_t sum;

  sum = __raw_cksum(buf, len, 0);
  return __raw_cksum_reduce(sum);
}

uint16_t ipv4_cksum(const struct rte_ipv4_hdr *ipv4_hdr) {
  uint16_t cksum;
  cksum = raw_cksum(ipv4_hdr, sizeof(struct rte_ipv4_hdr));
  return (uint16_t)~cksum;
}

uint16_t ipv4_udptcp_cksum(const struct rte_ipv4_hdr *ipv4_hdr,
                           const void *l4_hdr) {
  uint32_t cksum;
  uint32_t l3_len, l4_len;

  l3_len = rte_be_to_cpu_16(ipv4_hdr->total_length);
  if (l3_len < sizeof(struct rte_ipv4_hdr))
    return 0;

  l4_len = l3_len - sizeof(struct rte_ipv4_hdr);

  cksum = raw_cksum(l4_hdr, l4_len);
  cksum += ipv4_cksum(ipv4_hdr);

  cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
  cksum = (~cksum) & 0xffff;
  /*
   * Per RFC 768:If the computed checksum is zero for UDP,
   * it is transmitted as all ones
   * (the equivalent in one's complement arithmetic).
   */
  if (cksum == 0 && ipv4_hdr->next_proto_id == IPPROTO_UDP)
    cksum = 0xffff;

  return (uint16_t)cksum;
}

#define MAX_CHT_HEIGHT 40000

static uint64_t cht_loop(uint64_t k, uint64_t capacity) {
  uint64_t g = k % capacity;
  return g;
}

int cht_fill_cht(struct Vector *cht, uint32_t cht_height,
                 uint32_t backend_capacity) {
  // Generate the permutations of 0..(cht_height - 1) for each backend
  int *permutations =
      (int *)malloc(sizeof(int) * (int)(cht_height * backend_capacity));
  if (permutations == 0) {
    return 0;
  }

  for (uint32_t i = 0; i < backend_capacity; ++i) {
    uint32_t offset_absolut = i * 31;
    uint64_t offset = cht_loop(offset_absolut, cht_height);
    uint64_t base_shift = cht_loop(i, cht_height - 1);
    uint64_t shift = base_shift + 1;

    for (uint32_t j = 0; j < cht_height; ++j) {
      uint64_t permut = cht_loop(offset + shift * j, cht_height);
      permutations[i * cht_height + j] = (int)permut;
    }
  }

  int *next = (int *)malloc(sizeof(int) * (int)(cht_height));
  if (next == 0) {
    free(permutations);
    return 0;
  }

  for (uint32_t i = 0; i < cht_height; ++i) {
    next[i] = 0;
  }

  for (uint32_t i = 0; i < cht_height; ++i) {
    for (uint32_t j = 0; j < backend_capacity; ++j) {
      uint32_t *value;

      uint32_t index = j * cht_height + i;
      int bucket_id = permutations[index];
      int priority = next[bucket_id];

      next[bucket_id] += 1;

      vector_borrow(cht,
                    (int)(backend_capacity * ((uint32_t)bucket_id) +
                          ((uint32_t)priority)),
                    (void **)&value);
      *value = j;
      vector_return(cht,
                    (int)(backend_capacity * ((uint32_t)bucket_id) +
                          ((uint32_t)priority)),
                    (void *)value);
    }
  }

  // Free memory
  free(next);
  free(permutations);
  return 1;
}

int cht_find_preferred_available_backend(uint64_t hash, struct Vector *cht,
                                         struct DoubleChain *active_backends,
                                         uint32_t cht_height,
                                         uint32_t backend_capacity,
                                         int *chosen_backend) {
  uint64_t start = cht_loop(hash, cht_height);
  for (uint32_t i = 0; i < backend_capacity; ++i) {
    uint64_t candidate_idx =
        start * backend_capacity +
        i; // There was a bug, right here, untill I tried to prove this.

    uint32_t *candidate;
    vector_borrow(cht, (int)candidate_idx, (void **)&candidate);

    if (dchain_is_index_allocated(active_backends, (int)*candidate)) {
      *chosen_backend = (int)*candidate;
      vector_return(cht, (int)candidate_idx, candidate);
      return 1;
    }

    vector_return(cht, (int)candidate_idx, candidate);
  }

  return 0;
}

/**********************************************
 *
 *                  ETHER
 *
 **********************************************/

bool rte_ether_addr_eq(void *a, void *b) {
  struct rte_ether_addr *id1 = (struct rte_ether_addr *)a;
  struct rte_ether_addr *id2 = (struct rte_ether_addr *)b;

  return (id1->addr_bytes[0] == id2->addr_bytes[0])
      AND(id1->addr_bytes[1] == id2->addr_bytes[1])
          AND(id1->addr_bytes[2] == id2->addr_bytes[2])
              AND(id1->addr_bytes[3] == id2->addr_bytes[3])
                  AND(id1->addr_bytes[4] == id2->addr_bytes[4])
                      AND(id1->addr_bytes[5] == id2->addr_bytes[5]);
}

void rte_ether_addr_allocate(void *obj) {

  struct rte_ether_addr *id = (struct rte_ether_addr *)obj;

  id->addr_bytes[0] = 0;
  id->addr_bytes[1] = 0;
  id->addr_bytes[2] = 0;
  id->addr_bytes[3] = 0;
  id->addr_bytes[4] = 0;
  id->addr_bytes[5] = 0;
}

unsigned rte_ether_addr_hash(void *obj) {
  struct rte_ether_addr *id = (struct rte_ether_addr *)obj;

  uint8_t addr_bytes_0 = id->addr_bytes[0];
  uint8_t addr_bytes_1 = id->addr_bytes[1];
  uint8_t addr_bytes_2 = id->addr_bytes[2];
  uint8_t addr_bytes_3 = id->addr_bytes[3];
  uint8_t addr_bytes_4 = id->addr_bytes[4];
  uint8_t addr_bytes_5 = id->addr_bytes[5];

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, addr_bytes_0);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_1);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_2);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_3);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_4);
  hash = __builtin_ia32_crc32si(hash, addr_bytes_5);
  return hash;
}

/**********************************************
 *
 *                  NF
 *
 **********************************************/

bool nf_init(void);
int nf_process(uint16_t device, uint8_t *buffer, uint16_t packet_length,
               vigor_time_t now);

#define FLOOD_FRAME ((uint16_t)-1)

// Unverified support for batching, useful for performance comparisons
#define VIGOR_BATCH_SIZE 32

// Do the opposite: we want batching!
static const uint16_t RX_QUEUE_SIZE = 256;
static const uint16_t TX_QUEUE_SIZE = 256;

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 512;

// Send the given packet to all devices except the packet's own
void flood(struct rte_mbuf *packet, uint16_t nb_devices) {
  rte_mbuf_refcnt_set(packet, nb_devices - 1);
  int total_sent = 0;
  uint16_t skip_device = packet->port;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device != skip_device) {
      total_sent += rte_eth_tx_burst(device, 0, &packet, 1);
    }
  }
  // should not happen, but in case we couldn't transmit, ensure the packet is
  // freed
  if (total_sent != nb_devices - 1) {
    rte_mbuf_refcnt_set(packet, 1);
    rte_pktmbuf_free(packet);
  }
}

// Initializes the given device using the given memory pool
static int nf_init_device(uint16_t device, struct rte_mempool *mbuf_pool) {
  int retval;

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf = { 0 };
  // device_conf.rxmode.hw_strip_crc = 1;

  // Configure the device (1, 1 == number of RX/TX queues)
  retval = rte_eth_dev_configure(device, 1, 1, &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up a TX queue (NULL == default config)
  retval = rte_eth_tx_queue_setup(device, 0, TX_QUEUE_SIZE,
                                  rte_eth_dev_socket_id(device), NULL);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up RX queues (NULL == default config)
  retval = rte_eth_rx_queue_setup(
      device, 0, RX_QUEUE_SIZE, rte_eth_dev_socket_id(device), NULL, mbuf_pool);
  if (retval != 0) {
    return retval;
  }

  // Start the device
  retval = rte_eth_dev_start(device);
  if (retval != 0) {
    return retval;
  }

  // Enable RX in promiscuous mode, just in case
  rte_eth_promiscuous_enable(device);
  if (rte_eth_promiscuous_get(device) != 1) {
    return retval;
  }

  return 0;
}

// Main worker method (for now used on a single thread...)
static void worker_main(void) {
  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  printf("Core %u forwarding packets.\n", rte_lcore_id());

  if (rte_eth_dev_count_avail() != 2) {
    printf("We assume there will be exactly 2 devices for our simple batching "
           "implementation.\n");
    exit(1);
  }
  printf("Running with batches, this code is unverified!\n");

  while (1) {
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();
    for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;
         VIGOR_DEVICE++) {
      struct rte_mbuf *mbufs[VIGOR_BATCH_SIZE];
      uint16_t rx_count =
          rte_eth_rx_burst(VIGOR_DEVICE, 0, mbufs, VIGOR_BATCH_SIZE);

      struct rte_mbuf *mbufs_to_send[VIGOR_BATCH_SIZE];
      uint16_t tx_count = 0;
      for (uint16_t n = 0; n < rx_count; n++) {
        uint8_t *data = rte_pktmbuf_mtod(mbufs[n], uint8_t *);
        vigor_time_t VIGOR_NOW = current_time();
        uint16_t dst_device =
            nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, VIGOR_NOW);

        if (dst_device == VIGOR_DEVICE) {
          rte_pktmbuf_free(mbufs[n]);
        } else { // includes flood when 2 devices, which is equivalent to just
                 // a
                 // send
          mbufs_to_send[tx_count] = mbufs[n];
          tx_count++;
        }
      }

      uint16_t sent_count =
          rte_eth_tx_burst(1 - VIGOR_DEVICE, 0, mbufs_to_send, tx_count);
      for (uint16_t n = sent_count; n < tx_count; n++) {
        rte_pktmbuf_free(mbufs[n]); // should not happen, but we're in the
                                    // unverified case anyway
      }
    }
  }
}

// Entry point
int main(int argc, char **argv) {
  // Initialize the DPDK Environment Abstraction Layer (EAL)
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL initialization, ret=%d\n", ret);
  }
  argc -= ret;
  argv += ret;

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count_avail();
  struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
      "MEMPOOL",                         // name
      MEMPOOL_BUFFER_COUNT * nb_devices, // #elements
      0, // cache size (per-core, not useful in a single-threaded app)
      0, // application private area size
      RTE_MBUF_DEFAULT_BUF_SIZE, // data buffer size
      rte_socket_id()            // socket ID
  );
  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Cannot create pool: %s\n", rte_strerror(rte_errno));
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    ret = nf_init_device(device, mbuf_pool);
    if (ret == 0) {
      printf("Initialized device %" PRIu16 ".\n", device);
    } else {
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ": %d", device, ret);
    }
  }

  // Run!
  worker_main();

  return 0;
}

struct ip_addr {
  uint32_t addr;
};
struct DynamicValue {
  uint64_t bucket_size;
  int64_t bucket_time;
};
void ip_addr_allocate(void* obj) { (uintptr_t) obj; }
void DynamicValue_allocate(void* obj) {
  struct DynamicValue *dv = obj;
  dv->bucket_size = 0;
  dv->bucket_time = 0;
}
bool ip_addr_eq(void* a, void* b) {
  struct ip_addr *id1 = (struct ip_addr *)a;
  struct ip_addr *id2 = (struct ip_addr *)b;

  return (id1->addr == id2->addr);
}
uint32_t ip_addr_hash(void* obj) {
  struct ip_addr *id = (struct ip_addr *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->addr);
  return hash;
}



bool ip_addr_eq(void* a, void* b) ;
uint32_t ip_addr_hash(void* obj) ;
void DynamicValue_allocate(void* obj) ;
void ip_addr_allocate(void* obj) ;
struct Map* map;
struct DoubleChain* dchain;
struct Vector* vector;
struct Vector* vector_1;
struct Map* map_1;
struct DoubleChain* dchain_1;
struct Vector* vector_2;
struct Vector* vector_3;
struct Map* map_2;
struct DoubleChain* dchain_2;
struct Vector* vector_4;
struct Vector* vector_5;

bool nf_init() {
  int map_allocation_succeeded__1 = map_allocate(ip_addr_eq, ip_addr_hash, 65536u, &map);

  // 1891
  // 1892
  // 1893
  // 1894
  // 1895
  // 1896
  // 1897
  // 1898
  // 1899
  // 1900
  // 1901
  // 1902
  if (map_allocation_succeeded__1) {
    int is_dchain_allocated__4 = dchain_allocate(65536u, &dchain);

    // 1891
    // 1892
    // 1893
    // 1894
    // 1895
    // 1896
    // 1897
    // 1898
    // 1899
    // 1900
    // 1901
    if (is_dchain_allocated__4) {
      int vector_alloc_success__7 = vector_allocate(16u, 65536u, DynamicValue_allocate, &vector);

      // 1891
      // 1892
      // 1893
      // 1894
      // 1895
      // 1896
      // 1897
      // 1898
      // 1899
      // 1900
      if (vector_alloc_success__7) {
        int vector_alloc_success__10 = vector_allocate(4u, 65536u, ip_addr_allocate, &vector_1);

        // 1891
        // 1892
        // 1893
        // 1894
        // 1895
        // 1896
        // 1897
        // 1898
        // 1899
        if (vector_alloc_success__10) {
          int map_allocation_succeeded__13 = map_allocate(ip_addr_eq, ip_addr_hash, 65536u, &map_1);

          // 1891
          // 1892
          // 1893
          // 1894
          // 1895
          // 1896
          // 1897
          // 1898
          if (map_allocation_succeeded__13) {
            int is_dchain_allocated__16 = dchain_allocate(65536u, &dchain_1);

            // 1891
            // 1892
            // 1893
            // 1894
            // 1895
            // 1896
            // 1897
            if (is_dchain_allocated__16) {
              int vector_alloc_success__19 = vector_allocate(16u, 65536u, DynamicValue_allocate, &vector_2);

              // 1891
              // 1892
              // 1893
              // 1894
              // 1895
              // 1896
              if (vector_alloc_success__19) {
                int vector_alloc_success__22 = vector_allocate(4u, 65536u, ip_addr_allocate, &vector_3);

                // 1891
                // 1892
                // 1893
                // 1894
                // 1895
                if (vector_alloc_success__22) {
                  int map_allocation_succeeded__25 = map_allocate(ip_addr_eq, ip_addr_hash, 65536u, &map_2);

                  // 1891
                  // 1892
                  // 1893
                  // 1894
                  if (map_allocation_succeeded__25) {
                    int is_dchain_allocated__28 = dchain_allocate(65536u, &dchain_2);

                    // 1891
                    // 1892
                    // 1893
                    if (is_dchain_allocated__28) {
                      int vector_alloc_success__31 = vector_allocate(16u, 65536u, DynamicValue_allocate, &vector_4);

                      // 1891
                      // 1892
                      if (vector_alloc_success__31) {
                        int vector_alloc_success__34 = vector_allocate(4u, 65536u, ip_addr_allocate, &vector_5);

                        // 1891
                        if (vector_alloc_success__34) {
                          return 1;
                        }

                        // 1892
                        else {
                          return 0;
                        } // !vector_alloc_success__34

                      }

                      // 1893
                      else {
                        return 0;
                      } // !vector_alloc_success__31

                    }

                    // 1894
                    else {
                      return 0;
                    } // !is_dchain_allocated__28

                  }

                  // 1895
                  else {
                    return 0;
                  } // !map_allocation_succeeded__25

                }

                // 1896
                else {
                  return 0;
                } // !vector_alloc_success__22

              }

              // 1897
              else {
                return 0;
              } // !vector_alloc_success__19

            }

            // 1898
            else {
              return 0;
            } // !is_dchain_allocated__16

          }

          // 1899
          else {
            return 0;
          } // !map_allocation_succeeded__13

        }

        // 1900
        else {
          return 0;
        } // !vector_alloc_success__10

      }

      // 1901
      else {
        return 0;
      } // !vector_alloc_success__7

    }

    // 1902
    else {
      return 0;
    } // !is_dchain_allocated__4

  }

  // 1903
  else {
    return 0;
  } // !map_allocation_succeeded__1

}

int nf_process(uint16_t device, uint8_t* packet, uint16_t packet_length, int64_t now) {
  struct rte_ether_hdr* ether_header_1 = (struct rte_ether_hdr*)(packet);

  // 1905
  // 1906
  // 1907
  // 1908
  // 1909
  // 1910
  // 1911
  // 1912
  // 1913
  // 1914
  // 1915
  // 1916
  // 1917
  // 1918
  // 1919
  // 1920
  // 1921
  // 1922
  // 1923
  // 1924
  // 1925
  // 1926
  // 1927
  // 1928
  // 1929
  // 1930
  // 1931
  // 1932
  // 1933
  // 1934
  // 1935
  // 1936
  // 1937
  // 1938
  // 1939
  // 1940
  // 1941
  // 1942
  // 1943
  // 1944
  // 1945
  // 1946
  // 1947
  // 1948
  // 1949
  // 1950
  // 1951
  // 1952
  // 1953
  // 1954
  // 1955
  // 1956
  // 1957
  // 1958
  // 1959
  // 1960
  // 1961
  // 1962
  // 1963
  // 1964
  // 1965
  // 1966
  // 1967
  // 1968
  // 1969
  // 1970
  // 1971
  // 1972
  // 1973
  // 1974
  // 1975
  // 1976
  // 1977
  // 1978
  // 1979
  // 1980
  // 1981
  // 1982
  // 1983
  // 1984
  // 1985
  // 1986
  // 1987
  // 1988
  // 1989
  // 1990
  // 1991
  // 1992
  // 1993
  // 1994
  // 1995
  // 1996
  // 1997
  // 1998
  // 1999
  // 2000
  // 2001
  // 2002
  // 2003
  // 2004
  // 2005
  // 2006
  // 2007
  // 2008
  // 2009
  // 2010
  // 2011
  // 2012
  // 2013
  // 2014
  // 2015
  // 2016
  // 2017
  // 2018
  // 2019
  // 2020
  // 2021
  // 2022
  // 2023
  // 2024
  // 2025
  // 2026
  // 2027
  // 2028
  // 2029
  // 2030
  // 2031
  // 2032
  // 2033
  // 2034
  // 2035
  // 2036
  // 2037
  // 2038
  // 2039
  // 2040
  // 2041
  // 2042
  // 2043
  // 2044
  // 2045
  // 2046
  // 2047
  // 2048
  // 2049
  // 2050
  // 2051
  // 2052
  // 2053
  // 2054
  // 2055
  // 2056
  // 2057
  // 2058
  // 2059
  // 2060
  // 2061
  if ((8u == ether_header_1->ether_type) & (20ul <= (4294967282u + packet_length))) {
    struct rte_ipv4_hdr* ipv4_header_1 = (struct rte_ipv4_hdr*)(packet + 14u);
    int number_of_freed_flows__56 = expire_items_single_map(dchain, vector_1, map, now - 6000000000000000ul);
    int number_of_freed_flows__57 = expire_items_single_map(dchain_1, vector_3, map_1, now - 6000000000000000ul);
    int number_of_freed_flows__58 = expire_items_single_map(dchain_2, vector_5, map_2, now - 6000000000000000ul);

    // 1905
    if (0u != device) {
      return 0;
    }

    // 1906
    // 1907
    // 1908
    // 1909
    // 1910
    // 1911
    // 1912
    // 1913
    // 1914
    // 1915
    // 1916
    // 1917
    // 1918
    // 1919
    // 1920
    // 1921
    // 1922
    // 1923
    // 1924
    // 1925
    // 1926
    // 1927
    // 1928
    // 1929
    // 1930
    // 1931
    // 1932
    // 1933
    // 1934
    // 1935
    // 1936
    // 1937
    // 1938
    // 1939
    // 1940
    // 1941
    // 1942
    // 1943
    // 1944
    // 1945
    // 1946
    // 1947
    // 1948
    // 1949
    // 1950
    // 1951
    // 1952
    // 1953
    // 1954
    // 1955
    // 1956
    // 1957
    // 1958
    // 1959
    // 1960
    // 1961
    // 1962
    // 1963
    // 1964
    // 1965
    // 1966
    // 1967
    // 1968
    // 1969
    // 1970
    // 1971
    // 1972
    // 1973
    // 1974
    // 1975
    // 1976
    // 1977
    // 1978
    // 1979
    // 1980
    // 1981
    // 1982
    // 1983
    // 1984
    // 1985
    // 1986
    // 1987
    // 1988
    // 1989
    // 1990
    // 1991
    // 1992
    // 1993
    // 1994
    // 1995
    // 1996
    // 1997
    // 1998
    // 1999
    // 2000
    // 2001
    // 2002
    // 2003
    // 2004
    // 2005
    // 2006
    // 2007
    // 2008
    // 2009
    // 2010
    // 2011
    // 2012
    // 2013
    // 2014
    // 2015
    // 2016
    // 2017
    // 2018
    // 2019
    // 2020
    // 2021
    // 2022
    // 2023
    // 2024
    // 2025
    // 2026
    // 2027
    // 2028
    // 2029
    // 2030
    // 2031
    // 2032
    // 2033
    // 2034
    // 2035
    // 2036
    // 2037
    // 2038
    // 2039
    // 2040
    // 2041
    // 2042
    // 2043
    // 2044
    // 2045
    // 2046
    // 2047
    // 2048
    // 2049
    // 2050
    // 2051
    // 2052
    // 2053
    // 2054
    // 2055
    // 2056
    // 2057
    // 2058
    // 2059
    // 2060
    // 2061
    else {
      uint8_t map_key[4];
      map_key[0u] = ipv4_header_1->src_addr & 0xff;
      map_key[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
      map_key[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
      map_key[3u] = ((ipv4_header_1->src_addr & 4043309055u) >> 24ul) & 0xff;
      int map_value_out;
      int map_has_this_key__68 = map_get(map, map_key, &map_value_out);

      // 1906
      // 1907
      // 1908
      // 1909
      // 1910
      // 1911
      // 1912
      // 1913
      // 1914
      // 1915
      // 1916
      // 1917
      // 1918
      // 1919
      // 1920
      // 1921
      // 1922
      // 1923
      // 1924
      // 1925
      // 1926
      // 1927
      // 1928
      // 1929
      // 1930
      // 1931
      // 1932
      // 1933
      // 1934
      // 1935
      // 1936
      // 1937
      if (0u == map_has_this_key__68) {
        uint32_t new_index__71;
        int out_of_space__71 = !dchain_allocate_new_index(dchain, &new_index__71, now);

        // 1906
        // 1907
        // 1908
        // 1909
        // 1910
        // 1911
        // 1912
        // 1913
        // 1914
        // 1915
        // 1916
        // 1917
        // 1918
        // 1919
        // 1920
        // 1921
        // 1922
        // 1923
        // 1924
        // 1925
        // 1926
        // 1927
        // 1928
        // 1929
        // 1930
        // 1931
        // 1932
        // 1933
        // 1934
        // 1935
        // 1936
        if (false == ((out_of_space__71) & (0u == number_of_freed_flows__56))) {
          uint8_t* vector_value_out = 0u;
          vector_borrow(vector_1, new_index__71, (void**)(&vector_value_out));
          vector_value_out[0u] = ipv4_header_1->src_addr & 0xff;
          vector_value_out[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
          vector_value_out[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
          vector_value_out[3u] = ((ipv4_header_1->src_addr & 4043309055u) >> 24ul) & 0xff;
          uint8_t* vector_value_out_1 = 0u;
          vector_borrow(vector, new_index__71, (void**)(&vector_value_out_1));
          vector_value_out_1[0u] = 3750000000ul - packet_length;
          vector_value_out_1[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
          vector_value_out_1[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
          vector_value_out_1[3u] = 223u;
          vector_value_out_1[4u] = 0u;
          vector_value_out_1[5u] = 0u;
          vector_value_out_1[6u] = 0u;
          vector_value_out_1[7u] = 0u;
          vector_value_out_1[8u] = now & 0xff;
          vector_value_out_1[9u] = (now >> 8) & 0xff;
          vector_value_out_1[10u] = (now >> 16) & 0xff;
          vector_value_out_1[11u] = (now >> 24) & 0xff;
          vector_value_out_1[12u] = (now >> 32) & 0xff;
          vector_value_out_1[13u] = (now >> 40) & 0xff;
          vector_value_out_1[14u] = (now >> 48) & 0xff;
          vector_value_out_1[15u] = (now >> 56) & 0xff;
          map_put(map, vector_value_out, new_index__71);
          vector_return(vector_1, new_index__71, vector_value_out);
          vector_return(vector, new_index__71, vector_value_out_1);
          uint8_t map_key_1[4];
          map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
          map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
          map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
          map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
          int map_value_out_1;
          int map_has_this_key__79 = map_get(map_1, map_key_1, &map_value_out_1);

          // 1906
          // 1907
          // 1908
          // 1909
          // 1910
          // 1911
          // 1912
          if (0u == map_has_this_key__79) {
            uint32_t new_index__82;
            int out_of_space__82 = !dchain_allocate_new_index(dchain_1, &new_index__82, now);

            // 1906
            // 1907
            // 1908
            // 1909
            // 1910
            // 1911
            if (false == ((out_of_space__82) & (0u == number_of_freed_flows__57))) {
              uint8_t* vector_value_out_2 = 0u;
              vector_borrow(vector_3, new_index__82, (void**)(&vector_value_out_2));
              vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
              vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              vector_value_out_2[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
              uint8_t* vector_value_out_3 = 0u;
              vector_borrow(vector_2, new_index__82, (void**)(&vector_value_out_3));
              vector_value_out_3[0u] = 3750000000ul - packet_length;
              vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
              vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
              vector_value_out_3[3u] = 223u;
              vector_value_out_3[4u] = 0u;
              vector_value_out_3[5u] = 0u;
              vector_value_out_3[6u] = 0u;
              vector_value_out_3[7u] = 0u;
              vector_value_out_3[8u] = now & 0xff;
              vector_value_out_3[9u] = (now >> 8) & 0xff;
              vector_value_out_3[10u] = (now >> 16) & 0xff;
              vector_value_out_3[11u] = (now >> 24) & 0xff;
              vector_value_out_3[12u] = (now >> 32) & 0xff;
              vector_value_out_3[13u] = (now >> 40) & 0xff;
              vector_value_out_3[14u] = (now >> 48) & 0xff;
              vector_value_out_3[15u] = (now >> 56) & 0xff;
              map_put(map_1, vector_value_out_2, new_index__82);
              vector_return(vector_3, new_index__82, vector_value_out_2);
              vector_return(vector_2, new_index__82, vector_value_out_3);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__90 = map_get(map_2, map_key_2, &map_value_out_2);

              // 1906
              // 1907
              if (0u == map_has_this_key__90) {
                uint32_t new_index__93;
                int out_of_space__93 = !dchain_allocate_new_index(dchain_2, &new_index__93, now);

                // 1906
                if (false == ((out_of_space__93) & (0u == number_of_freed_flows__58))) {
                  uint8_t* vector_value_out_4 = 0u;
                  vector_borrow(vector_5, new_index__93, (void**)(&vector_value_out_4));
                  vector_value_out_4[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_4[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_4[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_4[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  uint8_t* vector_value_out_5 = 0u;
                  vector_borrow(vector_4, new_index__93, (void**)(&vector_value_out_5));
                  vector_value_out_5[0u] = 3750000000ul - packet_length;
                  vector_value_out_5[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_5[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_5[3u] = 223u;
                  vector_value_out_5[4u] = 0u;
                  vector_value_out_5[5u] = 0u;
                  vector_value_out_5[6u] = 0u;
                  vector_value_out_5[7u] = 0u;
                  vector_value_out_5[8u] = now & 0xff;
                  vector_value_out_5[9u] = (now >> 8) & 0xff;
                  vector_value_out_5[10u] = (now >> 16) & 0xff;
                  vector_value_out_5[11u] = (now >> 24) & 0xff;
                  vector_value_out_5[12u] = (now >> 32) & 0xff;
                  vector_value_out_5[13u] = (now >> 40) & 0xff;
                  vector_value_out_5[14u] = (now >> 48) & 0xff;
                  vector_value_out_5[15u] = (now >> 56) & 0xff;
                  map_put(map_2, vector_value_out_4, new_index__93);
                  vector_return(vector_5, new_index__93, vector_value_out_4);
                  vector_return(vector_4, new_index__93, vector_value_out_5);
                  return 1;
                }

                // 1907
                else {
                  return 1;
                } // !(false == ((out_of_space__93) & (0u == number_of_freed_flows__58)))

              }

              // 1908
              // 1909
              // 1910
              // 1911
              else {
                dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                uint8_t* vector_value_out_4 = 0u;
                vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_4));
                vector_value_out_4[0u] = 3750000000ul - packet_length;
                vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_4[3u] = 223u;
                vector_value_out_4[4u] = 0u;
                vector_value_out_4[5u] = 0u;
                vector_value_out_4[6u] = 0u;
                vector_value_out_4[7u] = 0u;
                vector_value_out_4[8u] = now & 0xff;
                vector_value_out_4[9u] = (now >> 8) & 0xff;
                vector_value_out_4[10u] = (now >> 16) & 0xff;
                vector_value_out_4[11u] = (now >> 24) & 0xff;
                vector_value_out_4[12u] = (now >> 32) & 0xff;
                vector_value_out_4[13u] = (now >> 40) & 0xff;
                vector_value_out_4[14u] = (now >> 48) & 0xff;
                vector_value_out_4[15u] = (now >> 56) & 0xff;

                // 1908
                // 1909
                // 1910
                if ((now - vector_value_out_4[8ul]) < 6000000000000000ul) {

                  // 1908
                  // 1909
                  if ((vector_value_out_4[0ul] + ((625ul * (now - vector_value_out_4[8ul])) / 1000000000ul)) <= 3750000000ul) {

                    // 1908
                    if ((vector_value_out_4[0ul] + ((625ul * (now - vector_value_out_4[8ul])) / 1000000000ul)) <= packet_length) {
                      vector_return(vector_4, map_value_out_2, vector_value_out_4);
                      return 1;
                    }

                    // 1909
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_4);
                      return 1;
                    } // !((vector_value_out_4[0ul] + ((625ul * (now - vector_value_out_4[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 1910
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_4);
                    return 1;
                  } // !((vector_value_out_4[0ul] + ((625ul * (now - vector_value_out_4[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 1911
                else {
                  vector_return(vector_4, map_value_out_2, vector_value_out_4);
                  return 1;
                } // !((now - vector_value_out_4[8ul]) < 6000000000000000ul)

              } // !(0u == map_has_this_key__90)

            }

            // 1912
            else {
              return 1;
            } // !(false == ((out_of_space__82) & (0u == number_of_freed_flows__57)))

          }

          // 1913
          // 1914
          // 1915
          // 1916
          // 1917
          // 1918
          // 1919
          // 1920
          // 1921
          // 1922
          // 1923
          // 1924
          // 1925
          // 1926
          // 1927
          // 1928
          // 1929
          // 1930
          // 1931
          // 1932
          // 1933
          // 1934
          // 1935
          // 1936
          else {
            dchain_rejuvenate_index(dchain_1, map_value_out_1, now);
            uint8_t* vector_value_out_2 = 0u;
            vector_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_2));
            vector_value_out_2[0u] = 3750000000ul - packet_length;
            vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
            vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
            vector_value_out_2[3u] = 223u;
            vector_value_out_2[4u] = 0u;
            vector_value_out_2[5u] = 0u;
            vector_value_out_2[6u] = 0u;
            vector_value_out_2[7u] = 0u;
            vector_value_out_2[8u] = now & 0xff;
            vector_value_out_2[9u] = (now >> 8) & 0xff;
            vector_value_out_2[10u] = (now >> 16) & 0xff;
            vector_value_out_2[11u] = (now >> 24) & 0xff;
            vector_value_out_2[12u] = (now >> 32) & 0xff;
            vector_value_out_2[13u] = (now >> 40) & 0xff;
            vector_value_out_2[14u] = (now >> 48) & 0xff;
            vector_value_out_2[15u] = (now >> 56) & 0xff;

            // 1913
            // 1914
            // 1915
            // 1916
            // 1917
            // 1918
            // 1919
            // 1920
            // 1921
            // 1922
            // 1923
            // 1924
            // 1925
            // 1926
            // 1927
            // 1928
            // 1929
            // 1930
            if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

              // 1913
              // 1914
              // 1915
              // 1916
              // 1917
              // 1918
              // 1919
              // 1920
              // 1921
              // 1922
              // 1923
              // 1924
              if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                // 1913
                // 1914
                // 1915
                // 1916
                // 1917
                // 1918
                if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                  vector_return(vector_2, map_value_out_1, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__171 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 1913
                  // 1914
                  if (0u == map_has_this_key__171) {
                    uint32_t new_index__174;
                    int out_of_space__174 = !dchain_allocate_new_index(dchain_2, &new_index__174, now);

                    // 1913
                    if (false == ((out_of_space__174) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_5, new_index__174, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_4 = 0u;
                      vector_borrow(vector_4, new_index__174, (void**)(&vector_value_out_4));
                      vector_value_out_4[0u] = 3750000000ul - packet_length;
                      vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_4[3u] = 223u;
                      vector_value_out_4[4u] = 0u;
                      vector_value_out_4[5u] = 0u;
                      vector_value_out_4[6u] = 0u;
                      vector_value_out_4[7u] = 0u;
                      vector_value_out_4[8u] = now & 0xff;
                      vector_value_out_4[9u] = (now >> 8) & 0xff;
                      vector_value_out_4[10u] = (now >> 16) & 0xff;
                      vector_value_out_4[11u] = (now >> 24) & 0xff;
                      vector_value_out_4[12u] = (now >> 32) & 0xff;
                      vector_value_out_4[13u] = (now >> 40) & 0xff;
                      vector_value_out_4[14u] = (now >> 48) & 0xff;
                      vector_value_out_4[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_3, new_index__174);
                      vector_return(vector_5, new_index__174, vector_value_out_3);
                      vector_return(vector_4, new_index__174, vector_value_out_4);
                      return 1;
                    }

                    // 1914
                    else {
                      return 1;
                    } // !(false == ((out_of_space__174) & (0u == number_of_freed_flows__58)))

                  }

                  // 1915
                  // 1916
                  // 1917
                  // 1918
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = 3750000000ul - packet_length;
                    vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_3[3u] = 223u;
                    vector_value_out_3[4u] = 0u;
                    vector_value_out_3[5u] = 0u;
                    vector_value_out_3[6u] = 0u;
                    vector_value_out_3[7u] = 0u;
                    vector_value_out_3[8u] = now & 0xff;
                    vector_value_out_3[9u] = (now >> 8) & 0xff;
                    vector_value_out_3[10u] = (now >> 16) & 0xff;
                    vector_value_out_3[11u] = (now >> 24) & 0xff;
                    vector_value_out_3[12u] = (now >> 32) & 0xff;
                    vector_value_out_3[13u] = (now >> 40) & 0xff;
                    vector_value_out_3[14u] = (now >> 48) & 0xff;
                    vector_value_out_3[15u] = (now >> 56) & 0xff;

                    // 1915
                    // 1916
                    // 1917
                    if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                      // 1915
                      // 1916
                      if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 1915
                        if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1916
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1917
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1918
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__171)

                }

                // 1919
                // 1920
                // 1921
                // 1922
                // 1923
                // 1924
                else {
                  vector_return(vector_2, map_value_out_1, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__237 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 1919
                  // 1920
                  if (0u == map_has_this_key__237) {
                    uint32_t new_index__240;
                    int out_of_space__240 = !dchain_allocate_new_index(dchain_2, &new_index__240, now);

                    // 1919
                    if (false == ((out_of_space__240) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_5, new_index__240, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_4 = 0u;
                      vector_borrow(vector_4, new_index__240, (void**)(&vector_value_out_4));
                      vector_value_out_4[0u] = 3750000000ul - packet_length;
                      vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_4[3u] = 223u;
                      vector_value_out_4[4u] = 0u;
                      vector_value_out_4[5u] = 0u;
                      vector_value_out_4[6u] = 0u;
                      vector_value_out_4[7u] = 0u;
                      vector_value_out_4[8u] = now & 0xff;
                      vector_value_out_4[9u] = (now >> 8) & 0xff;
                      vector_value_out_4[10u] = (now >> 16) & 0xff;
                      vector_value_out_4[11u] = (now >> 24) & 0xff;
                      vector_value_out_4[12u] = (now >> 32) & 0xff;
                      vector_value_out_4[13u] = (now >> 40) & 0xff;
                      vector_value_out_4[14u] = (now >> 48) & 0xff;
                      vector_value_out_4[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_3, new_index__240);
                      vector_return(vector_5, new_index__240, vector_value_out_3);
                      vector_return(vector_4, new_index__240, vector_value_out_4);
                      return 1;
                    }

                    // 1920
                    else {
                      return 1;
                    } // !(false == ((out_of_space__240) & (0u == number_of_freed_flows__58)))

                  }

                  // 1921
                  // 1922
                  // 1923
                  // 1924
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = 3750000000ul - packet_length;
                    vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_3[3u] = 223u;
                    vector_value_out_3[4u] = 0u;
                    vector_value_out_3[5u] = 0u;
                    vector_value_out_3[6u] = 0u;
                    vector_value_out_3[7u] = 0u;
                    vector_value_out_3[8u] = now & 0xff;
                    vector_value_out_3[9u] = (now >> 8) & 0xff;
                    vector_value_out_3[10u] = (now >> 16) & 0xff;
                    vector_value_out_3[11u] = (now >> 24) & 0xff;
                    vector_value_out_3[12u] = (now >> 32) & 0xff;
                    vector_value_out_3[13u] = (now >> 40) & 0xff;
                    vector_value_out_3[14u] = (now >> 48) & 0xff;
                    vector_value_out_3[15u] = (now >> 56) & 0xff;

                    // 1921
                    // 1922
                    // 1923
                    if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                      // 1921
                      // 1922
                      if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 1921
                        if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1922
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1923
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1924
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__237)

                } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

              }

              // 1925
              // 1926
              // 1927
              // 1928
              // 1929
              // 1930
              else {
                vector_return(vector_2, map_value_out_1, vector_value_out_2);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__303 = map_get(map_2, map_key_2, &map_value_out_2);

                // 1925
                // 1926
                if (0u == map_has_this_key__303) {
                  uint32_t new_index__306;
                  int out_of_space__306 = !dchain_allocate_new_index(dchain_2, &new_index__306, now);

                  // 1925
                  if (false == ((out_of_space__306) & (0u == number_of_freed_flows__58))) {
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_5, new_index__306, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    uint8_t* vector_value_out_4 = 0u;
                    vector_borrow(vector_4, new_index__306, (void**)(&vector_value_out_4));
                    vector_value_out_4[0u] = 3750000000ul - packet_length;
                    vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_4[3u] = 223u;
                    vector_value_out_4[4u] = 0u;
                    vector_value_out_4[5u] = 0u;
                    vector_value_out_4[6u] = 0u;
                    vector_value_out_4[7u] = 0u;
                    vector_value_out_4[8u] = now & 0xff;
                    vector_value_out_4[9u] = (now >> 8) & 0xff;
                    vector_value_out_4[10u] = (now >> 16) & 0xff;
                    vector_value_out_4[11u] = (now >> 24) & 0xff;
                    vector_value_out_4[12u] = (now >> 32) & 0xff;
                    vector_value_out_4[13u] = (now >> 40) & 0xff;
                    vector_value_out_4[14u] = (now >> 48) & 0xff;
                    vector_value_out_4[15u] = (now >> 56) & 0xff;
                    map_put(map_2, vector_value_out_3, new_index__306);
                    vector_return(vector_5, new_index__306, vector_value_out_3);
                    vector_return(vector_4, new_index__306, vector_value_out_4);
                    return 1;
                  }

                  // 1926
                  else {
                    return 1;
                  } // !(false == ((out_of_space__306) & (0u == number_of_freed_flows__58)))

                }

                // 1927
                // 1928
                // 1929
                // 1930
                else {
                  dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                  uint8_t* vector_value_out_3 = 0u;
                  vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = 3750000000ul - packet_length;
                  vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_3[3u] = 223u;
                  vector_value_out_3[4u] = 0u;
                  vector_value_out_3[5u] = 0u;
                  vector_value_out_3[6u] = 0u;
                  vector_value_out_3[7u] = 0u;
                  vector_value_out_3[8u] = now & 0xff;
                  vector_value_out_3[9u] = (now >> 8) & 0xff;
                  vector_value_out_3[10u] = (now >> 16) & 0xff;
                  vector_value_out_3[11u] = (now >> 24) & 0xff;
                  vector_value_out_3[12u] = (now >> 32) & 0xff;
                  vector_value_out_3[13u] = (now >> 40) & 0xff;
                  vector_value_out_3[14u] = (now >> 48) & 0xff;
                  vector_value_out_3[15u] = (now >> 56) & 0xff;

                  // 1927
                  // 1928
                  // 1929
                  if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                    // 1927
                    // 1928
                    if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                      // 1927
                      if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      }

                      // 1928
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 1929
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 1930
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_3);
                    return 1;
                  } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

                } // !(0u == map_has_this_key__303)

              } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

            }

            // 1931
            // 1932
            // 1933
            // 1934
            // 1935
            // 1936
            else {
              vector_return(vector_2, map_value_out_1, vector_value_out_2);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__369 = map_get(map_2, map_key_2, &map_value_out_2);

              // 1931
              // 1932
              if (0u == map_has_this_key__369) {
                uint32_t new_index__372;
                int out_of_space__372 = !dchain_allocate_new_index(dchain_2, &new_index__372, now);

                // 1931
                if (false == ((out_of_space__372) & (0u == number_of_freed_flows__58))) {
                  uint8_t* vector_value_out_3 = 0u;
                  vector_borrow(vector_5, new_index__372, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  uint8_t* vector_value_out_4 = 0u;
                  vector_borrow(vector_4, new_index__372, (void**)(&vector_value_out_4));
                  vector_value_out_4[0u] = 3750000000ul - packet_length;
                  vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_4[3u] = 223u;
                  vector_value_out_4[4u] = 0u;
                  vector_value_out_4[5u] = 0u;
                  vector_value_out_4[6u] = 0u;
                  vector_value_out_4[7u] = 0u;
                  vector_value_out_4[8u] = now & 0xff;
                  vector_value_out_4[9u] = (now >> 8) & 0xff;
                  vector_value_out_4[10u] = (now >> 16) & 0xff;
                  vector_value_out_4[11u] = (now >> 24) & 0xff;
                  vector_value_out_4[12u] = (now >> 32) & 0xff;
                  vector_value_out_4[13u] = (now >> 40) & 0xff;
                  vector_value_out_4[14u] = (now >> 48) & 0xff;
                  vector_value_out_4[15u] = (now >> 56) & 0xff;
                  map_put(map_2, vector_value_out_3, new_index__372);
                  vector_return(vector_5, new_index__372, vector_value_out_3);
                  vector_return(vector_4, new_index__372, vector_value_out_4);
                  return 1;
                }

                // 1932
                else {
                  return 1;
                } // !(false == ((out_of_space__372) & (0u == number_of_freed_flows__58)))

              }

              // 1933
              // 1934
              // 1935
              // 1936
              else {
                dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                uint8_t* vector_value_out_3 = 0u;
                vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                vector_value_out_3[0u] = 3750000000ul - packet_length;
                vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_3[3u] = 223u;
                vector_value_out_3[4u] = 0u;
                vector_value_out_3[5u] = 0u;
                vector_value_out_3[6u] = 0u;
                vector_value_out_3[7u] = 0u;
                vector_value_out_3[8u] = now & 0xff;
                vector_value_out_3[9u] = (now >> 8) & 0xff;
                vector_value_out_3[10u] = (now >> 16) & 0xff;
                vector_value_out_3[11u] = (now >> 24) & 0xff;
                vector_value_out_3[12u] = (now >> 32) & 0xff;
                vector_value_out_3[13u] = (now >> 40) & 0xff;
                vector_value_out_3[14u] = (now >> 48) & 0xff;
                vector_value_out_3[15u] = (now >> 56) & 0xff;

                // 1933
                // 1934
                // 1935
                if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                  // 1933
                  // 1934
                  if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                    // 1933
                    if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    }

                    // 1934
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 1935
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_3);
                    return 1;
                  } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 1936
                else {
                  vector_return(vector_4, map_value_out_2, vector_value_out_3);
                  return 1;
                } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

              } // !(0u == map_has_this_key__369)

            } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

          } // !(0u == map_has_this_key__79)

        }

        // 1937
        else {
          return 1;
        } // !(false == ((out_of_space__71) & (0u == number_of_freed_flows__56)))

      }

      // 1938
      // 1939
      // 1940
      // 1941
      // 1942
      // 1943
      // 1944
      // 1945
      // 1946
      // 1947
      // 1948
      // 1949
      // 1950
      // 1951
      // 1952
      // 1953
      // 1954
      // 1955
      // 1956
      // 1957
      // 1958
      // 1959
      // 1960
      // 1961
      // 1962
      // 1963
      // 1964
      // 1965
      // 1966
      // 1967
      // 1968
      // 1969
      // 1970
      // 1971
      // 1972
      // 1973
      // 1974
      // 1975
      // 1976
      // 1977
      // 1978
      // 1979
      // 1980
      // 1981
      // 1982
      // 1983
      // 1984
      // 1985
      // 1986
      // 1987
      // 1988
      // 1989
      // 1990
      // 1991
      // 1992
      // 1993
      // 1994
      // 1995
      // 1996
      // 1997
      // 1998
      // 1999
      // 2000
      // 2001
      // 2002
      // 2003
      // 2004
      // 2005
      // 2006
      // 2007
      // 2008
      // 2009
      // 2010
      // 2011
      // 2012
      // 2013
      // 2014
      // 2015
      // 2016
      // 2017
      // 2018
      // 2019
      // 2020
      // 2021
      // 2022
      // 2023
      // 2024
      // 2025
      // 2026
      // 2027
      // 2028
      // 2029
      // 2030
      // 2031
      // 2032
      // 2033
      // 2034
      // 2035
      // 2036
      // 2037
      // 2038
      // 2039
      // 2040
      // 2041
      // 2042
      // 2043
      // 2044
      // 2045
      // 2046
      // 2047
      // 2048
      // 2049
      // 2050
      // 2051
      // 2052
      // 2053
      // 2054
      // 2055
      // 2056
      // 2057
      // 2058
      // 2059
      // 2060
      // 2061
      else {
        dchain_rejuvenate_index(dchain, map_value_out, now);
        uint8_t* vector_value_out = 0u;
        vector_borrow(vector, map_value_out, (void**)(&vector_value_out));
        vector_value_out[0u] = 3750000000ul - packet_length;
        vector_value_out[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
        vector_value_out[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
        vector_value_out[3u] = 223u;
        vector_value_out[4u] = 0u;
        vector_value_out[5u] = 0u;
        vector_value_out[6u] = 0u;
        vector_value_out[7u] = 0u;
        vector_value_out[8u] = now & 0xff;
        vector_value_out[9u] = (now >> 8) & 0xff;
        vector_value_out[10u] = (now >> 16) & 0xff;
        vector_value_out[11u] = (now >> 24) & 0xff;
        vector_value_out[12u] = (now >> 32) & 0xff;
        vector_value_out[13u] = (now >> 40) & 0xff;
        vector_value_out[14u] = (now >> 48) & 0xff;
        vector_value_out[15u] = (now >> 56) & 0xff;

        // 1938
        // 1939
        // 1940
        // 1941
        // 1942
        // 1943
        // 1944
        // 1945
        // 1946
        // 1947
        // 1948
        // 1949
        // 1950
        // 1951
        // 1952
        // 1953
        // 1954
        // 1955
        // 1956
        // 1957
        // 1958
        // 1959
        // 1960
        // 1961
        // 1962
        // 1963
        // 1964
        // 1965
        // 1966
        // 1967
        // 1968
        // 1969
        // 1970
        // 1971
        // 1972
        // 1973
        // 1974
        // 1975
        // 1976
        // 1977
        // 1978
        // 1979
        // 1980
        // 1981
        // 1982
        // 1983
        // 1984
        // 1985
        // 1986
        // 1987
        // 1988
        // 1989
        // 1990
        // 1991
        // 1992
        // 1993
        // 1994
        // 1995
        // 1996
        // 1997
        // 1998
        // 1999
        // 2000
        // 2001
        // 2002
        // 2003
        // 2004
        // 2005
        // 2006
        // 2007
        // 2008
        // 2009
        // 2010
        // 2011
        // 2012
        // 2013
        // 2014
        // 2015
        // 2016
        // 2017
        // 2018
        // 2019
        // 2020
        // 2021
        // 2022
        // 2023
        // 2024
        // 2025
        // 2026
        // 2027
        // 2028
        // 2029
        // 2030
        if ((now - vector_value_out[8ul]) < 6000000000000000ul) {

          // 1938
          // 1939
          // 1940
          // 1941
          // 1942
          // 1943
          // 1944
          // 1945
          // 1946
          // 1947
          // 1948
          // 1949
          // 1950
          // 1951
          // 1952
          // 1953
          // 1954
          // 1955
          // 1956
          // 1957
          // 1958
          // 1959
          // 1960
          // 1961
          // 1962
          // 1963
          // 1964
          // 1965
          // 1966
          // 1967
          // 1968
          // 1969
          // 1970
          // 1971
          // 1972
          // 1973
          // 1974
          // 1975
          // 1976
          // 1977
          // 1978
          // 1979
          // 1980
          // 1981
          // 1982
          // 1983
          // 1984
          // 1985
          // 1986
          // 1987
          // 1988
          // 1989
          // 1990
          // 1991
          // 1992
          // 1993
          // 1994
          // 1995
          // 1996
          // 1997
          // 1998
          // 1999
          if ((vector_value_out[0ul] + ((625ul * (now - vector_value_out[8ul])) / 1000000000ul)) <= 3750000000ul) {

            // 1938
            // 1939
            // 1940
            // 1941
            // 1942
            // 1943
            // 1944
            // 1945
            // 1946
            // 1947
            // 1948
            // 1949
            // 1950
            // 1951
            // 1952
            // 1953
            // 1954
            // 1955
            // 1956
            // 1957
            // 1958
            // 1959
            // 1960
            // 1961
            // 1962
            // 1963
            // 1964
            // 1965
            // 1966
            // 1967
            // 1968
            if ((vector_value_out[0ul] + ((625ul * (now - vector_value_out[8ul])) / 1000000000ul)) <= packet_length) {
              vector_return(vector, map_value_out, vector_value_out);
              uint8_t map_key_1[4];
              map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
              int map_value_out_1;
              int map_has_this_key__450 = map_get(map_1, map_key_1, &map_value_out_1);

              // 1938
              // 1939
              // 1940
              // 1941
              // 1942
              // 1943
              // 1944
              if (0u == map_has_this_key__450) {
                uint32_t new_index__453;
                int out_of_space__453 = !dchain_allocate_new_index(dchain_1, &new_index__453, now);

                // 1938
                // 1939
                // 1940
                // 1941
                // 1942
                // 1943
                if (false == ((out_of_space__453) & (0u == number_of_freed_flows__57))) {
                  uint8_t* vector_value_out_1 = 0u;
                  vector_borrow(vector_3, new_index__453, (void**)(&vector_value_out_1));
                  vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
                  uint8_t* vector_value_out_2 = 0u;
                  vector_borrow(vector_2, new_index__453, (void**)(&vector_value_out_2));
                  vector_value_out_2[0u] = 3750000000ul - packet_length;
                  vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_2[3u] = 223u;
                  vector_value_out_2[4u] = 0u;
                  vector_value_out_2[5u] = 0u;
                  vector_value_out_2[6u] = 0u;
                  vector_value_out_2[7u] = 0u;
                  vector_value_out_2[8u] = now & 0xff;
                  vector_value_out_2[9u] = (now >> 8) & 0xff;
                  vector_value_out_2[10u] = (now >> 16) & 0xff;
                  vector_value_out_2[11u] = (now >> 24) & 0xff;
                  vector_value_out_2[12u] = (now >> 32) & 0xff;
                  vector_value_out_2[13u] = (now >> 40) & 0xff;
                  vector_value_out_2[14u] = (now >> 48) & 0xff;
                  vector_value_out_2[15u] = (now >> 56) & 0xff;
                  map_put(map_1, vector_value_out_1, new_index__453);
                  vector_return(vector_3, new_index__453, vector_value_out_1);
                  vector_return(vector_2, new_index__453, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__461 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 1938
                  // 1939
                  if (0u == map_has_this_key__461) {
                    uint32_t new_index__464;
                    int out_of_space__464 = !dchain_allocate_new_index(dchain_2, &new_index__464, now);

                    // 1938
                    if (false == ((out_of_space__464) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_5, new_index__464, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_4 = 0u;
                      vector_borrow(vector_4, new_index__464, (void**)(&vector_value_out_4));
                      vector_value_out_4[0u] = 3750000000ul - packet_length;
                      vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_4[3u] = 223u;
                      vector_value_out_4[4u] = 0u;
                      vector_value_out_4[5u] = 0u;
                      vector_value_out_4[6u] = 0u;
                      vector_value_out_4[7u] = 0u;
                      vector_value_out_4[8u] = now & 0xff;
                      vector_value_out_4[9u] = (now >> 8) & 0xff;
                      vector_value_out_4[10u] = (now >> 16) & 0xff;
                      vector_value_out_4[11u] = (now >> 24) & 0xff;
                      vector_value_out_4[12u] = (now >> 32) & 0xff;
                      vector_value_out_4[13u] = (now >> 40) & 0xff;
                      vector_value_out_4[14u] = (now >> 48) & 0xff;
                      vector_value_out_4[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_3, new_index__464);
                      vector_return(vector_5, new_index__464, vector_value_out_3);
                      vector_return(vector_4, new_index__464, vector_value_out_4);
                      return 1;
                    }

                    // 1939
                    else {
                      return 1;
                    } // !(false == ((out_of_space__464) & (0u == number_of_freed_flows__58)))

                  }

                  // 1940
                  // 1941
                  // 1942
                  // 1943
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = 3750000000ul - packet_length;
                    vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_3[3u] = 223u;
                    vector_value_out_3[4u] = 0u;
                    vector_value_out_3[5u] = 0u;
                    vector_value_out_3[6u] = 0u;
                    vector_value_out_3[7u] = 0u;
                    vector_value_out_3[8u] = now & 0xff;
                    vector_value_out_3[9u] = (now >> 8) & 0xff;
                    vector_value_out_3[10u] = (now >> 16) & 0xff;
                    vector_value_out_3[11u] = (now >> 24) & 0xff;
                    vector_value_out_3[12u] = (now >> 32) & 0xff;
                    vector_value_out_3[13u] = (now >> 40) & 0xff;
                    vector_value_out_3[14u] = (now >> 48) & 0xff;
                    vector_value_out_3[15u] = (now >> 56) & 0xff;

                    // 1940
                    // 1941
                    // 1942
                    if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                      // 1940
                      // 1941
                      if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 1940
                        if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1941
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1942
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1943
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__461)

                }

                // 1944
                else {
                  return 1;
                } // !(false == ((out_of_space__453) & (0u == number_of_freed_flows__57)))

              }

              // 1945
              // 1946
              // 1947
              // 1948
              // 1949
              // 1950
              // 1951
              // 1952
              // 1953
              // 1954
              // 1955
              // 1956
              // 1957
              // 1958
              // 1959
              // 1960
              // 1961
              // 1962
              // 1963
              // 1964
              // 1965
              // 1966
              // 1967
              // 1968
              else {
                dchain_rejuvenate_index(dchain_1, map_value_out_1, now);
                uint8_t* vector_value_out_1 = 0u;
                vector_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
                vector_value_out_1[0u] = 3750000000ul - packet_length;
                vector_value_out_1[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_1[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_1[3u] = 223u;
                vector_value_out_1[4u] = 0u;
                vector_value_out_1[5u] = 0u;
                vector_value_out_1[6u] = 0u;
                vector_value_out_1[7u] = 0u;
                vector_value_out_1[8u] = now & 0xff;
                vector_value_out_1[9u] = (now >> 8) & 0xff;
                vector_value_out_1[10u] = (now >> 16) & 0xff;
                vector_value_out_1[11u] = (now >> 24) & 0xff;
                vector_value_out_1[12u] = (now >> 32) & 0xff;
                vector_value_out_1[13u] = (now >> 40) & 0xff;
                vector_value_out_1[14u] = (now >> 48) & 0xff;
                vector_value_out_1[15u] = (now >> 56) & 0xff;

                // 1945
                // 1946
                // 1947
                // 1948
                // 1949
                // 1950
                // 1951
                // 1952
                // 1953
                // 1954
                // 1955
                // 1956
                // 1957
                // 1958
                // 1959
                // 1960
                // 1961
                // 1962
                if ((now - vector_value_out_1[8ul]) < 6000000000000000ul) {

                  // 1945
                  // 1946
                  // 1947
                  // 1948
                  // 1949
                  // 1950
                  // 1951
                  // 1952
                  // 1953
                  // 1954
                  // 1955
                  // 1956
                  if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul) {

                    // 1945
                    // 1946
                    // 1947
                    // 1948
                    // 1949
                    // 1950
                    if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length) {
                      vector_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__542 = map_get(map_2, map_key_2, &map_value_out_2);

                      // 1945
                      // 1946
                      if (0u == map_has_this_key__542) {
                        uint32_t new_index__545;
                        int out_of_space__545 = !dchain_allocate_new_index(dchain_2, &new_index__545, now);

                        // 1945
                        if (false == ((out_of_space__545) & (0u == number_of_freed_flows__58))) {
                          uint8_t* vector_value_out_2 = 0u;
                          vector_borrow(vector_5, new_index__545, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                          uint8_t* vector_value_out_3 = 0u;
                          vector_borrow(vector_4, new_index__545, (void**)(&vector_value_out_3));
                          vector_value_out_3[0u] = 3750000000ul - packet_length;
                          vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                          vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                          vector_value_out_3[3u] = 223u;
                          vector_value_out_3[4u] = 0u;
                          vector_value_out_3[5u] = 0u;
                          vector_value_out_3[6u] = 0u;
                          vector_value_out_3[7u] = 0u;
                          vector_value_out_3[8u] = now & 0xff;
                          vector_value_out_3[9u] = (now >> 8) & 0xff;
                          vector_value_out_3[10u] = (now >> 16) & 0xff;
                          vector_value_out_3[11u] = (now >> 24) & 0xff;
                          vector_value_out_3[12u] = (now >> 32) & 0xff;
                          vector_value_out_3[13u] = (now >> 40) & 0xff;
                          vector_value_out_3[14u] = (now >> 48) & 0xff;
                          vector_value_out_3[15u] = (now >> 56) & 0xff;
                          map_put(map_2, vector_value_out_2, new_index__545);
                          vector_return(vector_5, new_index__545, vector_value_out_2);
                          vector_return(vector_4, new_index__545, vector_value_out_3);
                          return 1;
                        }

                        // 1946
                        else {
                          return 1;
                        } // !(false == ((out_of_space__545) & (0u == number_of_freed_flows__58)))

                      }

                      // 1947
                      // 1948
                      // 1949
                      // 1950
                      else {
                        dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = 3750000000ul - packet_length;
                        vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_2[3u] = 223u;
                        vector_value_out_2[4u] = 0u;
                        vector_value_out_2[5u] = 0u;
                        vector_value_out_2[6u] = 0u;
                        vector_value_out_2[7u] = 0u;
                        vector_value_out_2[8u] = now & 0xff;
                        vector_value_out_2[9u] = (now >> 8) & 0xff;
                        vector_value_out_2[10u] = (now >> 16) & 0xff;
                        vector_value_out_2[11u] = (now >> 24) & 0xff;
                        vector_value_out_2[12u] = (now >> 32) & 0xff;
                        vector_value_out_2[13u] = (now >> 40) & 0xff;
                        vector_value_out_2[14u] = (now >> 48) & 0xff;
                        vector_value_out_2[15u] = (now >> 56) & 0xff;

                        // 1947
                        // 1948
                        // 1949
                        if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                          // 1947
                          // 1948
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                            // 1947
                            if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1948
                            else {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1949
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1950
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                      } // !(0u == map_has_this_key__542)

                    }

                    // 1951
                    // 1952
                    // 1953
                    // 1954
                    // 1955
                    // 1956
                    else {
                      vector_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__608 = map_get(map_2, map_key_2, &map_value_out_2);

                      // 1951
                      // 1952
                      if (0u == map_has_this_key__608) {
                        uint32_t new_index__611;
                        int out_of_space__611 = !dchain_allocate_new_index(dchain_2, &new_index__611, now);

                        // 1951
                        if (false == ((out_of_space__611) & (0u == number_of_freed_flows__58))) {
                          uint8_t* vector_value_out_2 = 0u;
                          vector_borrow(vector_5, new_index__611, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                          uint8_t* vector_value_out_3 = 0u;
                          vector_borrow(vector_4, new_index__611, (void**)(&vector_value_out_3));
                          vector_value_out_3[0u] = 3750000000ul - packet_length;
                          vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                          vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                          vector_value_out_3[3u] = 223u;
                          vector_value_out_3[4u] = 0u;
                          vector_value_out_3[5u] = 0u;
                          vector_value_out_3[6u] = 0u;
                          vector_value_out_3[7u] = 0u;
                          vector_value_out_3[8u] = now & 0xff;
                          vector_value_out_3[9u] = (now >> 8) & 0xff;
                          vector_value_out_3[10u] = (now >> 16) & 0xff;
                          vector_value_out_3[11u] = (now >> 24) & 0xff;
                          vector_value_out_3[12u] = (now >> 32) & 0xff;
                          vector_value_out_3[13u] = (now >> 40) & 0xff;
                          vector_value_out_3[14u] = (now >> 48) & 0xff;
                          vector_value_out_3[15u] = (now >> 56) & 0xff;
                          map_put(map_2, vector_value_out_2, new_index__611);
                          vector_return(vector_5, new_index__611, vector_value_out_2);
                          vector_return(vector_4, new_index__611, vector_value_out_3);
                          return 1;
                        }

                        // 1952
                        else {
                          return 1;
                        } // !(false == ((out_of_space__611) & (0u == number_of_freed_flows__58)))

                      }

                      // 1953
                      // 1954
                      // 1955
                      // 1956
                      else {
                        dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = 3750000000ul - packet_length;
                        vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_2[3u] = 223u;
                        vector_value_out_2[4u] = 0u;
                        vector_value_out_2[5u] = 0u;
                        vector_value_out_2[6u] = 0u;
                        vector_value_out_2[7u] = 0u;
                        vector_value_out_2[8u] = now & 0xff;
                        vector_value_out_2[9u] = (now >> 8) & 0xff;
                        vector_value_out_2[10u] = (now >> 16) & 0xff;
                        vector_value_out_2[11u] = (now >> 24) & 0xff;
                        vector_value_out_2[12u] = (now >> 32) & 0xff;
                        vector_value_out_2[13u] = (now >> 40) & 0xff;
                        vector_value_out_2[14u] = (now >> 48) & 0xff;
                        vector_value_out_2[15u] = (now >> 56) & 0xff;

                        // 1953
                        // 1954
                        // 1955
                        if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                          // 1953
                          // 1954
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                            // 1953
                            if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1954
                            else {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1955
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1956
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                      } // !(0u == map_has_this_key__608)

                    } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 1957
                  // 1958
                  // 1959
                  // 1960
                  // 1961
                  // 1962
                  else {
                    vector_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__674 = map_get(map_2, map_key_2, &map_value_out_2);

                    // 1957
                    // 1958
                    if (0u == map_has_this_key__674) {
                      uint32_t new_index__677;
                      int out_of_space__677 = !dchain_allocate_new_index(dchain_2, &new_index__677, now);

                      // 1957
                      if (false == ((out_of_space__677) & (0u == number_of_freed_flows__58))) {
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_5, new_index__677, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                        uint8_t* vector_value_out_3 = 0u;
                        vector_borrow(vector_4, new_index__677, (void**)(&vector_value_out_3));
                        vector_value_out_3[0u] = 3750000000ul - packet_length;
                        vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_3[3u] = 223u;
                        vector_value_out_3[4u] = 0u;
                        vector_value_out_3[5u] = 0u;
                        vector_value_out_3[6u] = 0u;
                        vector_value_out_3[7u] = 0u;
                        vector_value_out_3[8u] = now & 0xff;
                        vector_value_out_3[9u] = (now >> 8) & 0xff;
                        vector_value_out_3[10u] = (now >> 16) & 0xff;
                        vector_value_out_3[11u] = (now >> 24) & 0xff;
                        vector_value_out_3[12u] = (now >> 32) & 0xff;
                        vector_value_out_3[13u] = (now >> 40) & 0xff;
                        vector_value_out_3[14u] = (now >> 48) & 0xff;
                        vector_value_out_3[15u] = (now >> 56) & 0xff;
                        map_put(map_2, vector_value_out_2, new_index__677);
                        vector_return(vector_5, new_index__677, vector_value_out_2);
                        vector_return(vector_4, new_index__677, vector_value_out_3);
                        return 1;
                      }

                      // 1958
                      else {
                        return 1;
                      } // !(false == ((out_of_space__677) & (0u == number_of_freed_flows__58)))

                    }

                    // 1959
                    // 1960
                    // 1961
                    // 1962
                    else {
                      dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = 3750000000ul - packet_length;
                      vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_2[3u] = 223u;
                      vector_value_out_2[4u] = 0u;
                      vector_value_out_2[5u] = 0u;
                      vector_value_out_2[6u] = 0u;
                      vector_value_out_2[7u] = 0u;
                      vector_value_out_2[8u] = now & 0xff;
                      vector_value_out_2[9u] = (now >> 8) & 0xff;
                      vector_value_out_2[10u] = (now >> 16) & 0xff;
                      vector_value_out_2[11u] = (now >> 24) & 0xff;
                      vector_value_out_2[12u] = (now >> 32) & 0xff;
                      vector_value_out_2[13u] = (now >> 40) & 0xff;
                      vector_value_out_2[14u] = (now >> 48) & 0xff;
                      vector_value_out_2[15u] = (now >> 56) & 0xff;

                      // 1959
                      // 1960
                      // 1961
                      if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                        // 1959
                        // 1960
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                          // 1959
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 1960
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 1961
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 1962
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                    } // !(0u == map_has_this_key__674)

                  } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 1963
                // 1964
                // 1965
                // 1966
                // 1967
                // 1968
                else {
                  vector_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__740 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 1963
                  // 1964
                  if (0u == map_has_this_key__740) {
                    uint32_t new_index__743;
                    int out_of_space__743 = !dchain_allocate_new_index(dchain_2, &new_index__743, now);

                    // 1963
                    if (false == ((out_of_space__743) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_5, new_index__743, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_4, new_index__743, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = 3750000000ul - packet_length;
                      vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_3[3u] = 223u;
                      vector_value_out_3[4u] = 0u;
                      vector_value_out_3[5u] = 0u;
                      vector_value_out_3[6u] = 0u;
                      vector_value_out_3[7u] = 0u;
                      vector_value_out_3[8u] = now & 0xff;
                      vector_value_out_3[9u] = (now >> 8) & 0xff;
                      vector_value_out_3[10u] = (now >> 16) & 0xff;
                      vector_value_out_3[11u] = (now >> 24) & 0xff;
                      vector_value_out_3[12u] = (now >> 32) & 0xff;
                      vector_value_out_3[13u] = (now >> 40) & 0xff;
                      vector_value_out_3[14u] = (now >> 48) & 0xff;
                      vector_value_out_3[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_2, new_index__743);
                      vector_return(vector_5, new_index__743, vector_value_out_2);
                      vector_return(vector_4, new_index__743, vector_value_out_3);
                      return 1;
                    }

                    // 1964
                    else {
                      return 1;
                    } // !(false == ((out_of_space__743) & (0u == number_of_freed_flows__58)))

                  }

                  // 1965
                  // 1966
                  // 1967
                  // 1968
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = 3750000000ul - packet_length;
                    vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_2[3u] = 223u;
                    vector_value_out_2[4u] = 0u;
                    vector_value_out_2[5u] = 0u;
                    vector_value_out_2[6u] = 0u;
                    vector_value_out_2[7u] = 0u;
                    vector_value_out_2[8u] = now & 0xff;
                    vector_value_out_2[9u] = (now >> 8) & 0xff;
                    vector_value_out_2[10u] = (now >> 16) & 0xff;
                    vector_value_out_2[11u] = (now >> 24) & 0xff;
                    vector_value_out_2[12u] = (now >> 32) & 0xff;
                    vector_value_out_2[13u] = (now >> 40) & 0xff;
                    vector_value_out_2[14u] = (now >> 48) & 0xff;
                    vector_value_out_2[15u] = (now >> 56) & 0xff;

                    // 1965
                    // 1966
                    // 1967
                    if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                      // 1965
                      // 1966
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 1965
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 1966
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1967
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1968
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__740)

                } // !((now - vector_value_out_1[8ul]) < 6000000000000000ul)

              } // !(0u == map_has_this_key__450)

            }

            // 1969
            // 1970
            // 1971
            // 1972
            // 1973
            // 1974
            // 1975
            // 1976
            // 1977
            // 1978
            // 1979
            // 1980
            // 1981
            // 1982
            // 1983
            // 1984
            // 1985
            // 1986
            // 1987
            // 1988
            // 1989
            // 1990
            // 1991
            // 1992
            // 1993
            // 1994
            // 1995
            // 1996
            // 1997
            // 1998
            // 1999
            else {
              vector_return(vector, map_value_out, vector_value_out);
              uint8_t map_key_1[4];
              map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
              int map_value_out_1;
              int map_has_this_key__806 = map_get(map_1, map_key_1, &map_value_out_1);

              // 1969
              // 1970
              // 1971
              // 1972
              // 1973
              // 1974
              // 1975
              if (0u == map_has_this_key__806) {
                uint32_t new_index__809;
                int out_of_space__809 = !dchain_allocate_new_index(dchain_1, &new_index__809, now);

                // 1969
                // 1970
                // 1971
                // 1972
                // 1973
                // 1974
                if (false == ((out_of_space__809) & (0u == number_of_freed_flows__57))) {
                  uint8_t* vector_value_out_1 = 0u;
                  vector_borrow(vector_3, new_index__809, (void**)(&vector_value_out_1));
                  vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
                  uint8_t* vector_value_out_2 = 0u;
                  vector_borrow(vector_2, new_index__809, (void**)(&vector_value_out_2));
                  vector_value_out_2[0u] = 3750000000ul - packet_length;
                  vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_2[3u] = 223u;
                  vector_value_out_2[4u] = 0u;
                  vector_value_out_2[5u] = 0u;
                  vector_value_out_2[6u] = 0u;
                  vector_value_out_2[7u] = 0u;
                  vector_value_out_2[8u] = now & 0xff;
                  vector_value_out_2[9u] = (now >> 8) & 0xff;
                  vector_value_out_2[10u] = (now >> 16) & 0xff;
                  vector_value_out_2[11u] = (now >> 24) & 0xff;
                  vector_value_out_2[12u] = (now >> 32) & 0xff;
                  vector_value_out_2[13u] = (now >> 40) & 0xff;
                  vector_value_out_2[14u] = (now >> 48) & 0xff;
                  vector_value_out_2[15u] = (now >> 56) & 0xff;
                  map_put(map_1, vector_value_out_1, new_index__809);
                  vector_return(vector_3, new_index__809, vector_value_out_1);
                  vector_return(vector_2, new_index__809, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__817 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 1969
                  // 1970
                  if (0u == map_has_this_key__817) {
                    uint32_t new_index__820;
                    int out_of_space__820 = !dchain_allocate_new_index(dchain_2, &new_index__820, now);

                    // 1969
                    if (false == ((out_of_space__820) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_5, new_index__820, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_4 = 0u;
                      vector_borrow(vector_4, new_index__820, (void**)(&vector_value_out_4));
                      vector_value_out_4[0u] = 3750000000ul - packet_length;
                      vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_4[3u] = 223u;
                      vector_value_out_4[4u] = 0u;
                      vector_value_out_4[5u] = 0u;
                      vector_value_out_4[6u] = 0u;
                      vector_value_out_4[7u] = 0u;
                      vector_value_out_4[8u] = now & 0xff;
                      vector_value_out_4[9u] = (now >> 8) & 0xff;
                      vector_value_out_4[10u] = (now >> 16) & 0xff;
                      vector_value_out_4[11u] = (now >> 24) & 0xff;
                      vector_value_out_4[12u] = (now >> 32) & 0xff;
                      vector_value_out_4[13u] = (now >> 40) & 0xff;
                      vector_value_out_4[14u] = (now >> 48) & 0xff;
                      vector_value_out_4[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_3, new_index__820);
                      vector_return(vector_5, new_index__820, vector_value_out_3);
                      vector_return(vector_4, new_index__820, vector_value_out_4);
                      return 1;
                    }

                    // 1970
                    else {
                      return 1;
                    } // !(false == ((out_of_space__820) & (0u == number_of_freed_flows__58)))

                  }

                  // 1971
                  // 1972
                  // 1973
                  // 1974
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = 3750000000ul - packet_length;
                    vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_3[3u] = 223u;
                    vector_value_out_3[4u] = 0u;
                    vector_value_out_3[5u] = 0u;
                    vector_value_out_3[6u] = 0u;
                    vector_value_out_3[7u] = 0u;
                    vector_value_out_3[8u] = now & 0xff;
                    vector_value_out_3[9u] = (now >> 8) & 0xff;
                    vector_value_out_3[10u] = (now >> 16) & 0xff;
                    vector_value_out_3[11u] = (now >> 24) & 0xff;
                    vector_value_out_3[12u] = (now >> 32) & 0xff;
                    vector_value_out_3[13u] = (now >> 40) & 0xff;
                    vector_value_out_3[14u] = (now >> 48) & 0xff;
                    vector_value_out_3[15u] = (now >> 56) & 0xff;

                    // 1971
                    // 1972
                    // 1973
                    if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                      // 1971
                      // 1972
                      if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 1971
                        if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1972
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1973
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1974
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__817)

                }

                // 1975
                else {
                  return 1;
                } // !(false == ((out_of_space__809) & (0u == number_of_freed_flows__57)))

              }

              // 1976
              // 1977
              // 1978
              // 1979
              // 1980
              // 1981
              // 1982
              // 1983
              // 1984
              // 1985
              // 1986
              // 1987
              // 1988
              // 1989
              // 1990
              // 1991
              // 1992
              // 1993
              // 1994
              // 1995
              // 1996
              // 1997
              // 1998
              // 1999
              else {
                dchain_rejuvenate_index(dchain_1, map_value_out_1, now);
                uint8_t* vector_value_out_1 = 0u;
                vector_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
                vector_value_out_1[0u] = 3750000000ul - packet_length;
                vector_value_out_1[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_1[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_1[3u] = 223u;
                vector_value_out_1[4u] = 0u;
                vector_value_out_1[5u] = 0u;
                vector_value_out_1[6u] = 0u;
                vector_value_out_1[7u] = 0u;
                vector_value_out_1[8u] = now & 0xff;
                vector_value_out_1[9u] = (now >> 8) & 0xff;
                vector_value_out_1[10u] = (now >> 16) & 0xff;
                vector_value_out_1[11u] = (now >> 24) & 0xff;
                vector_value_out_1[12u] = (now >> 32) & 0xff;
                vector_value_out_1[13u] = (now >> 40) & 0xff;
                vector_value_out_1[14u] = (now >> 48) & 0xff;
                vector_value_out_1[15u] = (now >> 56) & 0xff;

                // 1976
                // 1977
                // 1978
                // 1979
                // 1980
                // 1981
                // 1982
                // 1983
                // 1984
                // 1985
                // 1986
                // 1987
                // 1988
                // 1989
                // 1990
                // 1991
                // 1992
                // 1993
                if ((now - vector_value_out_1[8ul]) < 6000000000000000ul) {

                  // 1976
                  // 1977
                  // 1978
                  // 1979
                  // 1980
                  // 1981
                  // 1982
                  // 1983
                  // 1984
                  // 1985
                  // 1986
                  // 1987
                  if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul) {

                    // 1976
                    // 1977
                    // 1978
                    // 1979
                    // 1980
                    // 1981
                    if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length) {
                      vector_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__898 = map_get(map_2, map_key_2, &map_value_out_2);

                      // 1976
                      // 1977
                      if (0u == map_has_this_key__898) {
                        uint32_t new_index__901;
                        int out_of_space__901 = !dchain_allocate_new_index(dchain_2, &new_index__901, now);

                        // 1976
                        if (false == ((out_of_space__901) & (0u == number_of_freed_flows__58))) {
                          uint8_t* vector_value_out_2 = 0u;
                          vector_borrow(vector_5, new_index__901, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                          uint8_t* vector_value_out_3 = 0u;
                          vector_borrow(vector_4, new_index__901, (void**)(&vector_value_out_3));
                          vector_value_out_3[0u] = 3750000000ul - packet_length;
                          vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                          vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                          vector_value_out_3[3u] = 223u;
                          vector_value_out_3[4u] = 0u;
                          vector_value_out_3[5u] = 0u;
                          vector_value_out_3[6u] = 0u;
                          vector_value_out_3[7u] = 0u;
                          vector_value_out_3[8u] = now & 0xff;
                          vector_value_out_3[9u] = (now >> 8) & 0xff;
                          vector_value_out_3[10u] = (now >> 16) & 0xff;
                          vector_value_out_3[11u] = (now >> 24) & 0xff;
                          vector_value_out_3[12u] = (now >> 32) & 0xff;
                          vector_value_out_3[13u] = (now >> 40) & 0xff;
                          vector_value_out_3[14u] = (now >> 48) & 0xff;
                          vector_value_out_3[15u] = (now >> 56) & 0xff;
                          map_put(map_2, vector_value_out_2, new_index__901);
                          vector_return(vector_5, new_index__901, vector_value_out_2);
                          vector_return(vector_4, new_index__901, vector_value_out_3);
                          return 1;
                        }

                        // 1977
                        else {
                          return 1;
                        } // !(false == ((out_of_space__901) & (0u == number_of_freed_flows__58)))

                      }

                      // 1978
                      // 1979
                      // 1980
                      // 1981
                      else {
                        dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = 3750000000ul - packet_length;
                        vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_2[3u] = 223u;
                        vector_value_out_2[4u] = 0u;
                        vector_value_out_2[5u] = 0u;
                        vector_value_out_2[6u] = 0u;
                        vector_value_out_2[7u] = 0u;
                        vector_value_out_2[8u] = now & 0xff;
                        vector_value_out_2[9u] = (now >> 8) & 0xff;
                        vector_value_out_2[10u] = (now >> 16) & 0xff;
                        vector_value_out_2[11u] = (now >> 24) & 0xff;
                        vector_value_out_2[12u] = (now >> 32) & 0xff;
                        vector_value_out_2[13u] = (now >> 40) & 0xff;
                        vector_value_out_2[14u] = (now >> 48) & 0xff;
                        vector_value_out_2[15u] = (now >> 56) & 0xff;

                        // 1978
                        // 1979
                        // 1980
                        if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                          // 1978
                          // 1979
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                            // 1978
                            if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1979
                            else {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1980
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1981
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                      } // !(0u == map_has_this_key__898)

                    }

                    // 1982
                    // 1983
                    // 1984
                    // 1985
                    // 1986
                    // 1987
                    else {
                      vector_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__964 = map_get(map_2, map_key_2, &map_value_out_2);

                      // 1982
                      // 1983
                      if (0u == map_has_this_key__964) {
                        uint32_t new_index__967;
                        int out_of_space__967 = !dchain_allocate_new_index(dchain_2, &new_index__967, now);

                        // 1982
                        if (false == ((out_of_space__967) & (0u == number_of_freed_flows__58))) {
                          uint8_t* vector_value_out_2 = 0u;
                          vector_borrow(vector_5, new_index__967, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                          uint8_t* vector_value_out_3 = 0u;
                          vector_borrow(vector_4, new_index__967, (void**)(&vector_value_out_3));
                          vector_value_out_3[0u] = 3750000000ul - packet_length;
                          vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                          vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                          vector_value_out_3[3u] = 223u;
                          vector_value_out_3[4u] = 0u;
                          vector_value_out_3[5u] = 0u;
                          vector_value_out_3[6u] = 0u;
                          vector_value_out_3[7u] = 0u;
                          vector_value_out_3[8u] = now & 0xff;
                          vector_value_out_3[9u] = (now >> 8) & 0xff;
                          vector_value_out_3[10u] = (now >> 16) & 0xff;
                          vector_value_out_3[11u] = (now >> 24) & 0xff;
                          vector_value_out_3[12u] = (now >> 32) & 0xff;
                          vector_value_out_3[13u] = (now >> 40) & 0xff;
                          vector_value_out_3[14u] = (now >> 48) & 0xff;
                          vector_value_out_3[15u] = (now >> 56) & 0xff;
                          map_put(map_2, vector_value_out_2, new_index__967);
                          vector_return(vector_5, new_index__967, vector_value_out_2);
                          vector_return(vector_4, new_index__967, vector_value_out_3);
                          return 1;
                        }

                        // 1983
                        else {
                          return 1;
                        } // !(false == ((out_of_space__967) & (0u == number_of_freed_flows__58)))

                      }

                      // 1984
                      // 1985
                      // 1986
                      // 1987
                      else {
                        dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = 3750000000ul - packet_length;
                        vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_2[3u] = 223u;
                        vector_value_out_2[4u] = 0u;
                        vector_value_out_2[5u] = 0u;
                        vector_value_out_2[6u] = 0u;
                        vector_value_out_2[7u] = 0u;
                        vector_value_out_2[8u] = now & 0xff;
                        vector_value_out_2[9u] = (now >> 8) & 0xff;
                        vector_value_out_2[10u] = (now >> 16) & 0xff;
                        vector_value_out_2[11u] = (now >> 24) & 0xff;
                        vector_value_out_2[12u] = (now >> 32) & 0xff;
                        vector_value_out_2[13u] = (now >> 40) & 0xff;
                        vector_value_out_2[14u] = (now >> 48) & 0xff;
                        vector_value_out_2[15u] = (now >> 56) & 0xff;

                        // 1984
                        // 1985
                        // 1986
                        if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                          // 1984
                          // 1985
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                            // 1984
                            if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1985
                            else {
                              vector_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1986
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1987
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                      } // !(0u == map_has_this_key__964)

                    } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 1988
                  // 1989
                  // 1990
                  // 1991
                  // 1992
                  // 1993
                  else {
                    vector_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__1030 = map_get(map_2, map_key_2, &map_value_out_2);

                    // 1988
                    // 1989
                    if (0u == map_has_this_key__1030) {
                      uint32_t new_index__1033;
                      int out_of_space__1033 = !dchain_allocate_new_index(dchain_2, &new_index__1033, now);

                      // 1988
                      if (false == ((out_of_space__1033) & (0u == number_of_freed_flows__58))) {
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_5, new_index__1033, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                        uint8_t* vector_value_out_3 = 0u;
                        vector_borrow(vector_4, new_index__1033, (void**)(&vector_value_out_3));
                        vector_value_out_3[0u] = 3750000000ul - packet_length;
                        vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_3[3u] = 223u;
                        vector_value_out_3[4u] = 0u;
                        vector_value_out_3[5u] = 0u;
                        vector_value_out_3[6u] = 0u;
                        vector_value_out_3[7u] = 0u;
                        vector_value_out_3[8u] = now & 0xff;
                        vector_value_out_3[9u] = (now >> 8) & 0xff;
                        vector_value_out_3[10u] = (now >> 16) & 0xff;
                        vector_value_out_3[11u] = (now >> 24) & 0xff;
                        vector_value_out_3[12u] = (now >> 32) & 0xff;
                        vector_value_out_3[13u] = (now >> 40) & 0xff;
                        vector_value_out_3[14u] = (now >> 48) & 0xff;
                        vector_value_out_3[15u] = (now >> 56) & 0xff;
                        map_put(map_2, vector_value_out_2, new_index__1033);
                        vector_return(vector_5, new_index__1033, vector_value_out_2);
                        vector_return(vector_4, new_index__1033, vector_value_out_3);
                        return 1;
                      }

                      // 1989
                      else {
                        return 1;
                      } // !(false == ((out_of_space__1033) & (0u == number_of_freed_flows__58)))

                    }

                    // 1990
                    // 1991
                    // 1992
                    // 1993
                    else {
                      dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = 3750000000ul - packet_length;
                      vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_2[3u] = 223u;
                      vector_value_out_2[4u] = 0u;
                      vector_value_out_2[5u] = 0u;
                      vector_value_out_2[6u] = 0u;
                      vector_value_out_2[7u] = 0u;
                      vector_value_out_2[8u] = now & 0xff;
                      vector_value_out_2[9u] = (now >> 8) & 0xff;
                      vector_value_out_2[10u] = (now >> 16) & 0xff;
                      vector_value_out_2[11u] = (now >> 24) & 0xff;
                      vector_value_out_2[12u] = (now >> 32) & 0xff;
                      vector_value_out_2[13u] = (now >> 40) & 0xff;
                      vector_value_out_2[14u] = (now >> 48) & 0xff;
                      vector_value_out_2[15u] = (now >> 56) & 0xff;

                      // 1990
                      // 1991
                      // 1992
                      if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                        // 1990
                        // 1991
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                          // 1990
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 1991
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 1992
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 1993
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                    } // !(0u == map_has_this_key__1030)

                  } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 1994
                // 1995
                // 1996
                // 1997
                // 1998
                // 1999
                else {
                  vector_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1096 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 1994
                  // 1995
                  if (0u == map_has_this_key__1096) {
                    uint32_t new_index__1099;
                    int out_of_space__1099 = !dchain_allocate_new_index(dchain_2, &new_index__1099, now);

                    // 1994
                    if (false == ((out_of_space__1099) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_5, new_index__1099, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_4, new_index__1099, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = 3750000000ul - packet_length;
                      vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_3[3u] = 223u;
                      vector_value_out_3[4u] = 0u;
                      vector_value_out_3[5u] = 0u;
                      vector_value_out_3[6u] = 0u;
                      vector_value_out_3[7u] = 0u;
                      vector_value_out_3[8u] = now & 0xff;
                      vector_value_out_3[9u] = (now >> 8) & 0xff;
                      vector_value_out_3[10u] = (now >> 16) & 0xff;
                      vector_value_out_3[11u] = (now >> 24) & 0xff;
                      vector_value_out_3[12u] = (now >> 32) & 0xff;
                      vector_value_out_3[13u] = (now >> 40) & 0xff;
                      vector_value_out_3[14u] = (now >> 48) & 0xff;
                      vector_value_out_3[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_2, new_index__1099);
                      vector_return(vector_5, new_index__1099, vector_value_out_2);
                      vector_return(vector_4, new_index__1099, vector_value_out_3);
                      return 1;
                    }

                    // 1995
                    else {
                      return 1;
                    } // !(false == ((out_of_space__1099) & (0u == number_of_freed_flows__58)))

                  }

                  // 1996
                  // 1997
                  // 1998
                  // 1999
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = 3750000000ul - packet_length;
                    vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_2[3u] = 223u;
                    vector_value_out_2[4u] = 0u;
                    vector_value_out_2[5u] = 0u;
                    vector_value_out_2[6u] = 0u;
                    vector_value_out_2[7u] = 0u;
                    vector_value_out_2[8u] = now & 0xff;
                    vector_value_out_2[9u] = (now >> 8) & 0xff;
                    vector_value_out_2[10u] = (now >> 16) & 0xff;
                    vector_value_out_2[11u] = (now >> 24) & 0xff;
                    vector_value_out_2[12u] = (now >> 32) & 0xff;
                    vector_value_out_2[13u] = (now >> 40) & 0xff;
                    vector_value_out_2[14u] = (now >> 48) & 0xff;
                    vector_value_out_2[15u] = (now >> 56) & 0xff;

                    // 1996
                    // 1997
                    // 1998
                    if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                      // 1996
                      // 1997
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 1996
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 1997
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1998
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1999
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__1096)

                } // !((now - vector_value_out_1[8ul]) < 6000000000000000ul)

              } // !(0u == map_has_this_key__806)

            } // !((vector_value_out[0ul] + ((625ul * (now - vector_value_out[8ul])) / 1000000000ul)) <= packet_length)

          }

          // 2000
          // 2001
          // 2002
          // 2003
          // 2004
          // 2005
          // 2006
          // 2007
          // 2008
          // 2009
          // 2010
          // 2011
          // 2012
          // 2013
          // 2014
          // 2015
          // 2016
          // 2017
          // 2018
          // 2019
          // 2020
          // 2021
          // 2022
          // 2023
          // 2024
          // 2025
          // 2026
          // 2027
          // 2028
          // 2029
          // 2030
          else {
            vector_return(vector, map_value_out, vector_value_out);
            uint8_t map_key_1[4];
            map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
            map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
            map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
            map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
            int map_value_out_1;
            int map_has_this_key__1162 = map_get(map_1, map_key_1, &map_value_out_1);

            // 2000
            // 2001
            // 2002
            // 2003
            // 2004
            // 2005
            // 2006
            if (0u == map_has_this_key__1162) {
              uint32_t new_index__1165;
              int out_of_space__1165 = !dchain_allocate_new_index(dchain_1, &new_index__1165, now);

              // 2000
              // 2001
              // 2002
              // 2003
              // 2004
              // 2005
              if (false == ((out_of_space__1165) & (0u == number_of_freed_flows__57))) {
                uint8_t* vector_value_out_1 = 0u;
                vector_borrow(vector_3, new_index__1165, (void**)(&vector_value_out_1));
                vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
                vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
                uint8_t* vector_value_out_2 = 0u;
                vector_borrow(vector_2, new_index__1165, (void**)(&vector_value_out_2));
                vector_value_out_2[0u] = 3750000000ul - packet_length;
                vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_2[3u] = 223u;
                vector_value_out_2[4u] = 0u;
                vector_value_out_2[5u] = 0u;
                vector_value_out_2[6u] = 0u;
                vector_value_out_2[7u] = 0u;
                vector_value_out_2[8u] = now & 0xff;
                vector_value_out_2[9u] = (now >> 8) & 0xff;
                vector_value_out_2[10u] = (now >> 16) & 0xff;
                vector_value_out_2[11u] = (now >> 24) & 0xff;
                vector_value_out_2[12u] = (now >> 32) & 0xff;
                vector_value_out_2[13u] = (now >> 40) & 0xff;
                vector_value_out_2[14u] = (now >> 48) & 0xff;
                vector_value_out_2[15u] = (now >> 56) & 0xff;
                map_put(map_1, vector_value_out_1, new_index__1165);
                vector_return(vector_3, new_index__1165, vector_value_out_1);
                vector_return(vector_2, new_index__1165, vector_value_out_2);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__1173 = map_get(map_2, map_key_2, &map_value_out_2);

                // 2000
                // 2001
                if (0u == map_has_this_key__1173) {
                  uint32_t new_index__1176;
                  int out_of_space__1176 = !dchain_allocate_new_index(dchain_2, &new_index__1176, now);

                  // 2000
                  if (false == ((out_of_space__1176) & (0u == number_of_freed_flows__58))) {
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_5, new_index__1176, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    uint8_t* vector_value_out_4 = 0u;
                    vector_borrow(vector_4, new_index__1176, (void**)(&vector_value_out_4));
                    vector_value_out_4[0u] = 3750000000ul - packet_length;
                    vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_4[3u] = 223u;
                    vector_value_out_4[4u] = 0u;
                    vector_value_out_4[5u] = 0u;
                    vector_value_out_4[6u] = 0u;
                    vector_value_out_4[7u] = 0u;
                    vector_value_out_4[8u] = now & 0xff;
                    vector_value_out_4[9u] = (now >> 8) & 0xff;
                    vector_value_out_4[10u] = (now >> 16) & 0xff;
                    vector_value_out_4[11u] = (now >> 24) & 0xff;
                    vector_value_out_4[12u] = (now >> 32) & 0xff;
                    vector_value_out_4[13u] = (now >> 40) & 0xff;
                    vector_value_out_4[14u] = (now >> 48) & 0xff;
                    vector_value_out_4[15u] = (now >> 56) & 0xff;
                    map_put(map_2, vector_value_out_3, new_index__1176);
                    vector_return(vector_5, new_index__1176, vector_value_out_3);
                    vector_return(vector_4, new_index__1176, vector_value_out_4);
                    return 1;
                  }

                  // 2001
                  else {
                    return 1;
                  } // !(false == ((out_of_space__1176) & (0u == number_of_freed_flows__58)))

                }

                // 2002
                // 2003
                // 2004
                // 2005
                else {
                  dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                  uint8_t* vector_value_out_3 = 0u;
                  vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = 3750000000ul - packet_length;
                  vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_3[3u] = 223u;
                  vector_value_out_3[4u] = 0u;
                  vector_value_out_3[5u] = 0u;
                  vector_value_out_3[6u] = 0u;
                  vector_value_out_3[7u] = 0u;
                  vector_value_out_3[8u] = now & 0xff;
                  vector_value_out_3[9u] = (now >> 8) & 0xff;
                  vector_value_out_3[10u] = (now >> 16) & 0xff;
                  vector_value_out_3[11u] = (now >> 24) & 0xff;
                  vector_value_out_3[12u] = (now >> 32) & 0xff;
                  vector_value_out_3[13u] = (now >> 40) & 0xff;
                  vector_value_out_3[14u] = (now >> 48) & 0xff;
                  vector_value_out_3[15u] = (now >> 56) & 0xff;

                  // 2002
                  // 2003
                  // 2004
                  if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                    // 2002
                    // 2003
                    if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                      // 2002
                      if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      }

                      // 2003
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 2004
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 2005
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_3);
                    return 1;
                  } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

                } // !(0u == map_has_this_key__1173)

              }

              // 2006
              else {
                return 1;
              } // !(false == ((out_of_space__1165) & (0u == number_of_freed_flows__57)))

            }

            // 2007
            // 2008
            // 2009
            // 2010
            // 2011
            // 2012
            // 2013
            // 2014
            // 2015
            // 2016
            // 2017
            // 2018
            // 2019
            // 2020
            // 2021
            // 2022
            // 2023
            // 2024
            // 2025
            // 2026
            // 2027
            // 2028
            // 2029
            // 2030
            else {
              dchain_rejuvenate_index(dchain_1, map_value_out_1, now);
              uint8_t* vector_value_out_1 = 0u;
              vector_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
              vector_value_out_1[0u] = 3750000000ul - packet_length;
              vector_value_out_1[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
              vector_value_out_1[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
              vector_value_out_1[3u] = 223u;
              vector_value_out_1[4u] = 0u;
              vector_value_out_1[5u] = 0u;
              vector_value_out_1[6u] = 0u;
              vector_value_out_1[7u] = 0u;
              vector_value_out_1[8u] = now & 0xff;
              vector_value_out_1[9u] = (now >> 8) & 0xff;
              vector_value_out_1[10u] = (now >> 16) & 0xff;
              vector_value_out_1[11u] = (now >> 24) & 0xff;
              vector_value_out_1[12u] = (now >> 32) & 0xff;
              vector_value_out_1[13u] = (now >> 40) & 0xff;
              vector_value_out_1[14u] = (now >> 48) & 0xff;
              vector_value_out_1[15u] = (now >> 56) & 0xff;

              // 2007
              // 2008
              // 2009
              // 2010
              // 2011
              // 2012
              // 2013
              // 2014
              // 2015
              // 2016
              // 2017
              // 2018
              // 2019
              // 2020
              // 2021
              // 2022
              // 2023
              // 2024
              if ((now - vector_value_out_1[8ul]) < 6000000000000000ul) {

                // 2007
                // 2008
                // 2009
                // 2010
                // 2011
                // 2012
                // 2013
                // 2014
                // 2015
                // 2016
                // 2017
                // 2018
                if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul) {

                  // 2007
                  // 2008
                  // 2009
                  // 2010
                  // 2011
                  // 2012
                  if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length) {
                    vector_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__1254 = map_get(map_2, map_key_2, &map_value_out_2);

                    // 2007
                    // 2008
                    if (0u == map_has_this_key__1254) {
                      uint32_t new_index__1257;
                      int out_of_space__1257 = !dchain_allocate_new_index(dchain_2, &new_index__1257, now);

                      // 2007
                      if (false == ((out_of_space__1257) & (0u == number_of_freed_flows__58))) {
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_5, new_index__1257, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                        uint8_t* vector_value_out_3 = 0u;
                        vector_borrow(vector_4, new_index__1257, (void**)(&vector_value_out_3));
                        vector_value_out_3[0u] = 3750000000ul - packet_length;
                        vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_3[3u] = 223u;
                        vector_value_out_3[4u] = 0u;
                        vector_value_out_3[5u] = 0u;
                        vector_value_out_3[6u] = 0u;
                        vector_value_out_3[7u] = 0u;
                        vector_value_out_3[8u] = now & 0xff;
                        vector_value_out_3[9u] = (now >> 8) & 0xff;
                        vector_value_out_3[10u] = (now >> 16) & 0xff;
                        vector_value_out_3[11u] = (now >> 24) & 0xff;
                        vector_value_out_3[12u] = (now >> 32) & 0xff;
                        vector_value_out_3[13u] = (now >> 40) & 0xff;
                        vector_value_out_3[14u] = (now >> 48) & 0xff;
                        vector_value_out_3[15u] = (now >> 56) & 0xff;
                        map_put(map_2, vector_value_out_2, new_index__1257);
                        vector_return(vector_5, new_index__1257, vector_value_out_2);
                        vector_return(vector_4, new_index__1257, vector_value_out_3);
                        return 1;
                      }

                      // 2008
                      else {
                        return 1;
                      } // !(false == ((out_of_space__1257) & (0u == number_of_freed_flows__58)))

                    }

                    // 2009
                    // 2010
                    // 2011
                    // 2012
                    else {
                      dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = 3750000000ul - packet_length;
                      vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_2[3u] = 223u;
                      vector_value_out_2[4u] = 0u;
                      vector_value_out_2[5u] = 0u;
                      vector_value_out_2[6u] = 0u;
                      vector_value_out_2[7u] = 0u;
                      vector_value_out_2[8u] = now & 0xff;
                      vector_value_out_2[9u] = (now >> 8) & 0xff;
                      vector_value_out_2[10u] = (now >> 16) & 0xff;
                      vector_value_out_2[11u] = (now >> 24) & 0xff;
                      vector_value_out_2[12u] = (now >> 32) & 0xff;
                      vector_value_out_2[13u] = (now >> 40) & 0xff;
                      vector_value_out_2[14u] = (now >> 48) & 0xff;
                      vector_value_out_2[15u] = (now >> 56) & 0xff;

                      // 2009
                      // 2010
                      // 2011
                      if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                        // 2009
                        // 2010
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                          // 2009
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 2010
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 2011
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 2012
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                    } // !(0u == map_has_this_key__1254)

                  }

                  // 2013
                  // 2014
                  // 2015
                  // 2016
                  // 2017
                  // 2018
                  else {
                    vector_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__1320 = map_get(map_2, map_key_2, &map_value_out_2);

                    // 2013
                    // 2014
                    if (0u == map_has_this_key__1320) {
                      uint32_t new_index__1323;
                      int out_of_space__1323 = !dchain_allocate_new_index(dchain_2, &new_index__1323, now);

                      // 2013
                      if (false == ((out_of_space__1323) & (0u == number_of_freed_flows__58))) {
                        uint8_t* vector_value_out_2 = 0u;
                        vector_borrow(vector_5, new_index__1323, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                        uint8_t* vector_value_out_3 = 0u;
                        vector_borrow(vector_4, new_index__1323, (void**)(&vector_value_out_3));
                        vector_value_out_3[0u] = 3750000000ul - packet_length;
                        vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                        vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                        vector_value_out_3[3u] = 223u;
                        vector_value_out_3[4u] = 0u;
                        vector_value_out_3[5u] = 0u;
                        vector_value_out_3[6u] = 0u;
                        vector_value_out_3[7u] = 0u;
                        vector_value_out_3[8u] = now & 0xff;
                        vector_value_out_3[9u] = (now >> 8) & 0xff;
                        vector_value_out_3[10u] = (now >> 16) & 0xff;
                        vector_value_out_3[11u] = (now >> 24) & 0xff;
                        vector_value_out_3[12u] = (now >> 32) & 0xff;
                        vector_value_out_3[13u] = (now >> 40) & 0xff;
                        vector_value_out_3[14u] = (now >> 48) & 0xff;
                        vector_value_out_3[15u] = (now >> 56) & 0xff;
                        map_put(map_2, vector_value_out_2, new_index__1323);
                        vector_return(vector_5, new_index__1323, vector_value_out_2);
                        vector_return(vector_4, new_index__1323, vector_value_out_3);
                        return 1;
                      }

                      // 2014
                      else {
                        return 1;
                      } // !(false == ((out_of_space__1323) & (0u == number_of_freed_flows__58)))

                    }

                    // 2015
                    // 2016
                    // 2017
                    // 2018
                    else {
                      dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = 3750000000ul - packet_length;
                      vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_2[3u] = 223u;
                      vector_value_out_2[4u] = 0u;
                      vector_value_out_2[5u] = 0u;
                      vector_value_out_2[6u] = 0u;
                      vector_value_out_2[7u] = 0u;
                      vector_value_out_2[8u] = now & 0xff;
                      vector_value_out_2[9u] = (now >> 8) & 0xff;
                      vector_value_out_2[10u] = (now >> 16) & 0xff;
                      vector_value_out_2[11u] = (now >> 24) & 0xff;
                      vector_value_out_2[12u] = (now >> 32) & 0xff;
                      vector_value_out_2[13u] = (now >> 40) & 0xff;
                      vector_value_out_2[14u] = (now >> 48) & 0xff;
                      vector_value_out_2[15u] = (now >> 56) & 0xff;

                      // 2015
                      // 2016
                      // 2017
                      if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                        // 2015
                        // 2016
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                          // 2015
                          if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 2016
                          else {
                            vector_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 2017
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 2018
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                    } // !(0u == map_has_this_key__1320)

                  } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length)

                }

                // 2019
                // 2020
                // 2021
                // 2022
                // 2023
                // 2024
                else {
                  vector_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1386 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 2019
                  // 2020
                  if (0u == map_has_this_key__1386) {
                    uint32_t new_index__1389;
                    int out_of_space__1389 = !dchain_allocate_new_index(dchain_2, &new_index__1389, now);

                    // 2019
                    if (false == ((out_of_space__1389) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_5, new_index__1389, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_4, new_index__1389, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = 3750000000ul - packet_length;
                      vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_3[3u] = 223u;
                      vector_value_out_3[4u] = 0u;
                      vector_value_out_3[5u] = 0u;
                      vector_value_out_3[6u] = 0u;
                      vector_value_out_3[7u] = 0u;
                      vector_value_out_3[8u] = now & 0xff;
                      vector_value_out_3[9u] = (now >> 8) & 0xff;
                      vector_value_out_3[10u] = (now >> 16) & 0xff;
                      vector_value_out_3[11u] = (now >> 24) & 0xff;
                      vector_value_out_3[12u] = (now >> 32) & 0xff;
                      vector_value_out_3[13u] = (now >> 40) & 0xff;
                      vector_value_out_3[14u] = (now >> 48) & 0xff;
                      vector_value_out_3[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_2, new_index__1389);
                      vector_return(vector_5, new_index__1389, vector_value_out_2);
                      vector_return(vector_4, new_index__1389, vector_value_out_3);
                      return 1;
                    }

                    // 2020
                    else {
                      return 1;
                    } // !(false == ((out_of_space__1389) & (0u == number_of_freed_flows__58)))

                  }

                  // 2021
                  // 2022
                  // 2023
                  // 2024
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = 3750000000ul - packet_length;
                    vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_2[3u] = 223u;
                    vector_value_out_2[4u] = 0u;
                    vector_value_out_2[5u] = 0u;
                    vector_value_out_2[6u] = 0u;
                    vector_value_out_2[7u] = 0u;
                    vector_value_out_2[8u] = now & 0xff;
                    vector_value_out_2[9u] = (now >> 8) & 0xff;
                    vector_value_out_2[10u] = (now >> 16) & 0xff;
                    vector_value_out_2[11u] = (now >> 24) & 0xff;
                    vector_value_out_2[12u] = (now >> 32) & 0xff;
                    vector_value_out_2[13u] = (now >> 40) & 0xff;
                    vector_value_out_2[14u] = (now >> 48) & 0xff;
                    vector_value_out_2[15u] = (now >> 56) & 0xff;

                    // 2021
                    // 2022
                    // 2023
                    if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                      // 2021
                      // 2022
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 2021
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 2022
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 2023
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 2024
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__1386)

                } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul)

              }

              // 2025
              // 2026
              // 2027
              // 2028
              // 2029
              // 2030
              else {
                vector_return(vector_2, map_value_out_1, vector_value_out_1);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__1452 = map_get(map_2, map_key_2, &map_value_out_2);

                // 2025
                // 2026
                if (0u == map_has_this_key__1452) {
                  uint32_t new_index__1455;
                  int out_of_space__1455 = !dchain_allocate_new_index(dchain_2, &new_index__1455, now);

                  // 2025
                  if (false == ((out_of_space__1455) & (0u == number_of_freed_flows__58))) {
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_5, new_index__1455, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_4, new_index__1455, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = 3750000000ul - packet_length;
                    vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_3[3u] = 223u;
                    vector_value_out_3[4u] = 0u;
                    vector_value_out_3[5u] = 0u;
                    vector_value_out_3[6u] = 0u;
                    vector_value_out_3[7u] = 0u;
                    vector_value_out_3[8u] = now & 0xff;
                    vector_value_out_3[9u] = (now >> 8) & 0xff;
                    vector_value_out_3[10u] = (now >> 16) & 0xff;
                    vector_value_out_3[11u] = (now >> 24) & 0xff;
                    vector_value_out_3[12u] = (now >> 32) & 0xff;
                    vector_value_out_3[13u] = (now >> 40) & 0xff;
                    vector_value_out_3[14u] = (now >> 48) & 0xff;
                    vector_value_out_3[15u] = (now >> 56) & 0xff;
                    map_put(map_2, vector_value_out_2, new_index__1455);
                    vector_return(vector_5, new_index__1455, vector_value_out_2);
                    vector_return(vector_4, new_index__1455, vector_value_out_3);
                    return 1;
                  }

                  // 2026
                  else {
                    return 1;
                  } // !(false == ((out_of_space__1455) & (0u == number_of_freed_flows__58)))

                }

                // 2027
                // 2028
                // 2029
                // 2030
                else {
                  dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                  uint8_t* vector_value_out_2 = 0u;
                  vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                  vector_value_out_2[0u] = 3750000000ul - packet_length;
                  vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_2[3u] = 223u;
                  vector_value_out_2[4u] = 0u;
                  vector_value_out_2[5u] = 0u;
                  vector_value_out_2[6u] = 0u;
                  vector_value_out_2[7u] = 0u;
                  vector_value_out_2[8u] = now & 0xff;
                  vector_value_out_2[9u] = (now >> 8) & 0xff;
                  vector_value_out_2[10u] = (now >> 16) & 0xff;
                  vector_value_out_2[11u] = (now >> 24) & 0xff;
                  vector_value_out_2[12u] = (now >> 32) & 0xff;
                  vector_value_out_2[13u] = (now >> 40) & 0xff;
                  vector_value_out_2[14u] = (now >> 48) & 0xff;
                  vector_value_out_2[15u] = (now >> 56) & 0xff;

                  // 2027
                  // 2028
                  // 2029
                  if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                    // 2027
                    // 2028
                    if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                      // 2027
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      }

                      // 2028
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 2029
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 2030
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_2);
                    return 1;
                  } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                } // !(0u == map_has_this_key__1452)

              } // !((now - vector_value_out_1[8ul]) < 6000000000000000ul)

            } // !(0u == map_has_this_key__1162)

          } // !((vector_value_out[0ul] + ((625ul * (now - vector_value_out[8ul])) / 1000000000ul)) <= 3750000000ul)

        }

        // 2031
        // 2032
        // 2033
        // 2034
        // 2035
        // 2036
        // 2037
        // 2038
        // 2039
        // 2040
        // 2041
        // 2042
        // 2043
        // 2044
        // 2045
        // 2046
        // 2047
        // 2048
        // 2049
        // 2050
        // 2051
        // 2052
        // 2053
        // 2054
        // 2055
        // 2056
        // 2057
        // 2058
        // 2059
        // 2060
        // 2061
        else {
          vector_return(vector, map_value_out, vector_value_out);
          uint8_t map_key_1[4];
          map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
          map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
          map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
          map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
          int map_value_out_1;
          int map_has_this_key__1518 = map_get(map_1, map_key_1, &map_value_out_1);

          // 2031
          // 2032
          // 2033
          // 2034
          // 2035
          // 2036
          // 2037
          if (0u == map_has_this_key__1518) {
            uint32_t new_index__1521;
            int out_of_space__1521 = !dchain_allocate_new_index(dchain_1, &new_index__1521, now);

            // 2031
            // 2032
            // 2033
            // 2034
            // 2035
            // 2036
            if (false == ((out_of_space__1521) & (0u == number_of_freed_flows__57))) {
              uint8_t* vector_value_out_1 = 0u;
              vector_borrow(vector_3, new_index__1521, (void**)(&vector_value_out_1));
              vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
              vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
              uint8_t* vector_value_out_2 = 0u;
              vector_borrow(vector_2, new_index__1521, (void**)(&vector_value_out_2));
              vector_value_out_2[0u] = 3750000000ul - packet_length;
              vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
              vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
              vector_value_out_2[3u] = 223u;
              vector_value_out_2[4u] = 0u;
              vector_value_out_2[5u] = 0u;
              vector_value_out_2[6u] = 0u;
              vector_value_out_2[7u] = 0u;
              vector_value_out_2[8u] = now & 0xff;
              vector_value_out_2[9u] = (now >> 8) & 0xff;
              vector_value_out_2[10u] = (now >> 16) & 0xff;
              vector_value_out_2[11u] = (now >> 24) & 0xff;
              vector_value_out_2[12u] = (now >> 32) & 0xff;
              vector_value_out_2[13u] = (now >> 40) & 0xff;
              vector_value_out_2[14u] = (now >> 48) & 0xff;
              vector_value_out_2[15u] = (now >> 56) & 0xff;
              map_put(map_1, vector_value_out_1, new_index__1521);
              vector_return(vector_3, new_index__1521, vector_value_out_1);
              vector_return(vector_2, new_index__1521, vector_value_out_2);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__1529 = map_get(map_2, map_key_2, &map_value_out_2);

              // 2031
              // 2032
              if (0u == map_has_this_key__1529) {
                uint32_t new_index__1532;
                int out_of_space__1532 = !dchain_allocate_new_index(dchain_2, &new_index__1532, now);

                // 2031
                if (false == ((out_of_space__1532) & (0u == number_of_freed_flows__58))) {
                  uint8_t* vector_value_out_3 = 0u;
                  vector_borrow(vector_5, new_index__1532, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  uint8_t* vector_value_out_4 = 0u;
                  vector_borrow(vector_4, new_index__1532, (void**)(&vector_value_out_4));
                  vector_value_out_4[0u] = 3750000000ul - packet_length;
                  vector_value_out_4[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_4[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_4[3u] = 223u;
                  vector_value_out_4[4u] = 0u;
                  vector_value_out_4[5u] = 0u;
                  vector_value_out_4[6u] = 0u;
                  vector_value_out_4[7u] = 0u;
                  vector_value_out_4[8u] = now & 0xff;
                  vector_value_out_4[9u] = (now >> 8) & 0xff;
                  vector_value_out_4[10u] = (now >> 16) & 0xff;
                  vector_value_out_4[11u] = (now >> 24) & 0xff;
                  vector_value_out_4[12u] = (now >> 32) & 0xff;
                  vector_value_out_4[13u] = (now >> 40) & 0xff;
                  vector_value_out_4[14u] = (now >> 48) & 0xff;
                  vector_value_out_4[15u] = (now >> 56) & 0xff;
                  map_put(map_2, vector_value_out_3, new_index__1532);
                  vector_return(vector_5, new_index__1532, vector_value_out_3);
                  vector_return(vector_4, new_index__1532, vector_value_out_4);
                  return 1;
                }

                // 2032
                else {
                  return 1;
                } // !(false == ((out_of_space__1532) & (0u == number_of_freed_flows__58)))

              }

              // 2033
              // 2034
              // 2035
              // 2036
              else {
                dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                uint8_t* vector_value_out_3 = 0u;
                vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
                vector_value_out_3[0u] = 3750000000ul - packet_length;
                vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_3[3u] = 223u;
                vector_value_out_3[4u] = 0u;
                vector_value_out_3[5u] = 0u;
                vector_value_out_3[6u] = 0u;
                vector_value_out_3[7u] = 0u;
                vector_value_out_3[8u] = now & 0xff;
                vector_value_out_3[9u] = (now >> 8) & 0xff;
                vector_value_out_3[10u] = (now >> 16) & 0xff;
                vector_value_out_3[11u] = (now >> 24) & 0xff;
                vector_value_out_3[12u] = (now >> 32) & 0xff;
                vector_value_out_3[13u] = (now >> 40) & 0xff;
                vector_value_out_3[14u] = (now >> 48) & 0xff;
                vector_value_out_3[15u] = (now >> 56) & 0xff;

                // 2033
                // 2034
                // 2035
                if ((now - vector_value_out_3[8ul]) < 6000000000000000ul) {

                  // 2033
                  // 2034
                  if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul) {

                    // 2033
                    if ((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length) {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    }

                    // 2034
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 2035
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_3);
                    return 1;
                  } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 2036
                else {
                  vector_return(vector_4, map_value_out_2, vector_value_out_3);
                  return 1;
                } // !((now - vector_value_out_3[8ul]) < 6000000000000000ul)

              } // !(0u == map_has_this_key__1529)

            }

            // 2037
            else {
              return 1;
            } // !(false == ((out_of_space__1521) & (0u == number_of_freed_flows__57)))

          }

          // 2038
          // 2039
          // 2040
          // 2041
          // 2042
          // 2043
          // 2044
          // 2045
          // 2046
          // 2047
          // 2048
          // 2049
          // 2050
          // 2051
          // 2052
          // 2053
          // 2054
          // 2055
          // 2056
          // 2057
          // 2058
          // 2059
          // 2060
          // 2061
          else {
            dchain_rejuvenate_index(dchain_1, map_value_out_1, now);
            uint8_t* vector_value_out_1 = 0u;
            vector_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
            vector_value_out_1[0u] = 3750000000ul - packet_length;
            vector_value_out_1[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
            vector_value_out_1[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
            vector_value_out_1[3u] = 223u;
            vector_value_out_1[4u] = 0u;
            vector_value_out_1[5u] = 0u;
            vector_value_out_1[6u] = 0u;
            vector_value_out_1[7u] = 0u;
            vector_value_out_1[8u] = now & 0xff;
            vector_value_out_1[9u] = (now >> 8) & 0xff;
            vector_value_out_1[10u] = (now >> 16) & 0xff;
            vector_value_out_1[11u] = (now >> 24) & 0xff;
            vector_value_out_1[12u] = (now >> 32) & 0xff;
            vector_value_out_1[13u] = (now >> 40) & 0xff;
            vector_value_out_1[14u] = (now >> 48) & 0xff;
            vector_value_out_1[15u] = (now >> 56) & 0xff;

            // 2038
            // 2039
            // 2040
            // 2041
            // 2042
            // 2043
            // 2044
            // 2045
            // 2046
            // 2047
            // 2048
            // 2049
            // 2050
            // 2051
            // 2052
            // 2053
            // 2054
            // 2055
            if ((now - vector_value_out_1[8ul]) < 6000000000000000ul) {

              // 2038
              // 2039
              // 2040
              // 2041
              // 2042
              // 2043
              // 2044
              // 2045
              // 2046
              // 2047
              // 2048
              // 2049
              if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul) {

                // 2038
                // 2039
                // 2040
                // 2041
                // 2042
                // 2043
                if ((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length) {
                  vector_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1610 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 2038
                  // 2039
                  if (0u == map_has_this_key__1610) {
                    uint32_t new_index__1613;
                    int out_of_space__1613 = !dchain_allocate_new_index(dchain_2, &new_index__1613, now);

                    // 2038
                    if (false == ((out_of_space__1613) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_5, new_index__1613, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_4, new_index__1613, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = 3750000000ul - packet_length;
                      vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_3[3u] = 223u;
                      vector_value_out_3[4u] = 0u;
                      vector_value_out_3[5u] = 0u;
                      vector_value_out_3[6u] = 0u;
                      vector_value_out_3[7u] = 0u;
                      vector_value_out_3[8u] = now & 0xff;
                      vector_value_out_3[9u] = (now >> 8) & 0xff;
                      vector_value_out_3[10u] = (now >> 16) & 0xff;
                      vector_value_out_3[11u] = (now >> 24) & 0xff;
                      vector_value_out_3[12u] = (now >> 32) & 0xff;
                      vector_value_out_3[13u] = (now >> 40) & 0xff;
                      vector_value_out_3[14u] = (now >> 48) & 0xff;
                      vector_value_out_3[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_2, new_index__1613);
                      vector_return(vector_5, new_index__1613, vector_value_out_2);
                      vector_return(vector_4, new_index__1613, vector_value_out_3);
                      return 1;
                    }

                    // 2039
                    else {
                      return 1;
                    } // !(false == ((out_of_space__1613) & (0u == number_of_freed_flows__58)))

                  }

                  // 2040
                  // 2041
                  // 2042
                  // 2043
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = 3750000000ul - packet_length;
                    vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_2[3u] = 223u;
                    vector_value_out_2[4u] = 0u;
                    vector_value_out_2[5u] = 0u;
                    vector_value_out_2[6u] = 0u;
                    vector_value_out_2[7u] = 0u;
                    vector_value_out_2[8u] = now & 0xff;
                    vector_value_out_2[9u] = (now >> 8) & 0xff;
                    vector_value_out_2[10u] = (now >> 16) & 0xff;
                    vector_value_out_2[11u] = (now >> 24) & 0xff;
                    vector_value_out_2[12u] = (now >> 32) & 0xff;
                    vector_value_out_2[13u] = (now >> 40) & 0xff;
                    vector_value_out_2[14u] = (now >> 48) & 0xff;
                    vector_value_out_2[15u] = (now >> 56) & 0xff;

                    // 2040
                    // 2041
                    // 2042
                    if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                      // 2040
                      // 2041
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 2040
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 2041
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 2042
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 2043
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__1610)

                }

                // 2044
                // 2045
                // 2046
                // 2047
                // 2048
                // 2049
                else {
                  vector_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1676 = map_get(map_2, map_key_2, &map_value_out_2);

                  // 2044
                  // 2045
                  if (0u == map_has_this_key__1676) {
                    uint32_t new_index__1679;
                    int out_of_space__1679 = !dchain_allocate_new_index(dchain_2, &new_index__1679, now);

                    // 2044
                    if (false == ((out_of_space__1679) & (0u == number_of_freed_flows__58))) {
                      uint8_t* vector_value_out_2 = 0u;
                      vector_borrow(vector_5, new_index__1679, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      uint8_t* vector_value_out_3 = 0u;
                      vector_borrow(vector_4, new_index__1679, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = 3750000000ul - packet_length;
                      vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                      vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                      vector_value_out_3[3u] = 223u;
                      vector_value_out_3[4u] = 0u;
                      vector_value_out_3[5u] = 0u;
                      vector_value_out_3[6u] = 0u;
                      vector_value_out_3[7u] = 0u;
                      vector_value_out_3[8u] = now & 0xff;
                      vector_value_out_3[9u] = (now >> 8) & 0xff;
                      vector_value_out_3[10u] = (now >> 16) & 0xff;
                      vector_value_out_3[11u] = (now >> 24) & 0xff;
                      vector_value_out_3[12u] = (now >> 32) & 0xff;
                      vector_value_out_3[13u] = (now >> 40) & 0xff;
                      vector_value_out_3[14u] = (now >> 48) & 0xff;
                      vector_value_out_3[15u] = (now >> 56) & 0xff;
                      map_put(map_2, vector_value_out_2, new_index__1679);
                      vector_return(vector_5, new_index__1679, vector_value_out_2);
                      vector_return(vector_4, new_index__1679, vector_value_out_3);
                      return 1;
                    }

                    // 2045
                    else {
                      return 1;
                    } // !(false == ((out_of_space__1679) & (0u == number_of_freed_flows__58)))

                  }

                  // 2046
                  // 2047
                  // 2048
                  // 2049
                  else {
                    dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = 3750000000ul - packet_length;
                    vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_2[3u] = 223u;
                    vector_value_out_2[4u] = 0u;
                    vector_value_out_2[5u] = 0u;
                    vector_value_out_2[6u] = 0u;
                    vector_value_out_2[7u] = 0u;
                    vector_value_out_2[8u] = now & 0xff;
                    vector_value_out_2[9u] = (now >> 8) & 0xff;
                    vector_value_out_2[10u] = (now >> 16) & 0xff;
                    vector_value_out_2[11u] = (now >> 24) & 0xff;
                    vector_value_out_2[12u] = (now >> 32) & 0xff;
                    vector_value_out_2[13u] = (now >> 40) & 0xff;
                    vector_value_out_2[14u] = (now >> 48) & 0xff;
                    vector_value_out_2[15u] = (now >> 56) & 0xff;

                    // 2046
                    // 2047
                    // 2048
                    if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                      // 2046
                      // 2047
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                        // 2046
                        if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 2047
                        else {
                          vector_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 2048
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 2049
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                  } // !(0u == map_has_this_key__1676)

                } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= packet_length)

              }

              // 2050
              // 2051
              // 2052
              // 2053
              // 2054
              // 2055
              else {
                vector_return(vector_2, map_value_out_1, vector_value_out_1);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__1742 = map_get(map_2, map_key_2, &map_value_out_2);

                // 2050
                // 2051
                if (0u == map_has_this_key__1742) {
                  uint32_t new_index__1745;
                  int out_of_space__1745 = !dchain_allocate_new_index(dchain_2, &new_index__1745, now);

                  // 2050
                  if (false == ((out_of_space__1745) & (0u == number_of_freed_flows__58))) {
                    uint8_t* vector_value_out_2 = 0u;
                    vector_borrow(vector_5, new_index__1745, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    uint8_t* vector_value_out_3 = 0u;
                    vector_borrow(vector_4, new_index__1745, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = 3750000000ul - packet_length;
                    vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                    vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                    vector_value_out_3[3u] = 223u;
                    vector_value_out_3[4u] = 0u;
                    vector_value_out_3[5u] = 0u;
                    vector_value_out_3[6u] = 0u;
                    vector_value_out_3[7u] = 0u;
                    vector_value_out_3[8u] = now & 0xff;
                    vector_value_out_3[9u] = (now >> 8) & 0xff;
                    vector_value_out_3[10u] = (now >> 16) & 0xff;
                    vector_value_out_3[11u] = (now >> 24) & 0xff;
                    vector_value_out_3[12u] = (now >> 32) & 0xff;
                    vector_value_out_3[13u] = (now >> 40) & 0xff;
                    vector_value_out_3[14u] = (now >> 48) & 0xff;
                    vector_value_out_3[15u] = (now >> 56) & 0xff;
                    map_put(map_2, vector_value_out_2, new_index__1745);
                    vector_return(vector_5, new_index__1745, vector_value_out_2);
                    vector_return(vector_4, new_index__1745, vector_value_out_3);
                    return 1;
                  }

                  // 2051
                  else {
                    return 1;
                  } // !(false == ((out_of_space__1745) & (0u == number_of_freed_flows__58)))

                }

                // 2052
                // 2053
                // 2054
                // 2055
                else {
                  dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                  uint8_t* vector_value_out_2 = 0u;
                  vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                  vector_value_out_2[0u] = 3750000000ul - packet_length;
                  vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_2[3u] = 223u;
                  vector_value_out_2[4u] = 0u;
                  vector_value_out_2[5u] = 0u;
                  vector_value_out_2[6u] = 0u;
                  vector_value_out_2[7u] = 0u;
                  vector_value_out_2[8u] = now & 0xff;
                  vector_value_out_2[9u] = (now >> 8) & 0xff;
                  vector_value_out_2[10u] = (now >> 16) & 0xff;
                  vector_value_out_2[11u] = (now >> 24) & 0xff;
                  vector_value_out_2[12u] = (now >> 32) & 0xff;
                  vector_value_out_2[13u] = (now >> 40) & 0xff;
                  vector_value_out_2[14u] = (now >> 48) & 0xff;
                  vector_value_out_2[15u] = (now >> 56) & 0xff;

                  // 2052
                  // 2053
                  // 2054
                  if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                    // 2052
                    // 2053
                    if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                      // 2052
                      if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      }

                      // 2053
                      else {
                        vector_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 2054
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 2055
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_2);
                    return 1;
                  } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

                } // !(0u == map_has_this_key__1742)

              } // !((vector_value_out_1[0ul] + ((625ul * (now - vector_value_out_1[8ul])) / 1000000000ul)) <= 3750000000ul)

            }

            // 2056
            // 2057
            // 2058
            // 2059
            // 2060
            // 2061
            else {
              vector_return(vector_2, map_value_out_1, vector_value_out_1);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__1808 = map_get(map_2, map_key_2, &map_value_out_2);

              // 2056
              // 2057
              if (0u == map_has_this_key__1808) {
                uint32_t new_index__1811;
                int out_of_space__1811 = !dchain_allocate_new_index(dchain_2, &new_index__1811, now);

                // 2056
                if (false == ((out_of_space__1811) & (0u == number_of_freed_flows__58))) {
                  uint8_t* vector_value_out_2 = 0u;
                  vector_borrow(vector_5, new_index__1811, (void**)(&vector_value_out_2));
                  vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  uint8_t* vector_value_out_3 = 0u;
                  vector_borrow(vector_4, new_index__1811, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = 3750000000ul - packet_length;
                  vector_value_out_3[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                  vector_value_out_3[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                  vector_value_out_3[3u] = 223u;
                  vector_value_out_3[4u] = 0u;
                  vector_value_out_3[5u] = 0u;
                  vector_value_out_3[6u] = 0u;
                  vector_value_out_3[7u] = 0u;
                  vector_value_out_3[8u] = now & 0xff;
                  vector_value_out_3[9u] = (now >> 8) & 0xff;
                  vector_value_out_3[10u] = (now >> 16) & 0xff;
                  vector_value_out_3[11u] = (now >> 24) & 0xff;
                  vector_value_out_3[12u] = (now >> 32) & 0xff;
                  vector_value_out_3[13u] = (now >> 40) & 0xff;
                  vector_value_out_3[14u] = (now >> 48) & 0xff;
                  vector_value_out_3[15u] = (now >> 56) & 0xff;
                  map_put(map_2, vector_value_out_2, new_index__1811);
                  vector_return(vector_5, new_index__1811, vector_value_out_2);
                  vector_return(vector_4, new_index__1811, vector_value_out_3);
                  return 1;
                }

                // 2057
                else {
                  return 1;
                } // !(false == ((out_of_space__1811) & (0u == number_of_freed_flows__58)))

              }

              // 2058
              // 2059
              // 2060
              // 2061
              else {
                dchain_rejuvenate_index(dchain_2, map_value_out_2, now);
                uint8_t* vector_value_out_2 = 0u;
                vector_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
                vector_value_out_2[0u] = 3750000000ul - packet_length;
                vector_value_out_2[1u] = ((3750000000ul - packet_length) >> 8ul) & 0xff;
                vector_value_out_2[2u] = ((3750000000ul - packet_length) >> 16ul) & 0xff;
                vector_value_out_2[3u] = 223u;
                vector_value_out_2[4u] = 0u;
                vector_value_out_2[5u] = 0u;
                vector_value_out_2[6u] = 0u;
                vector_value_out_2[7u] = 0u;
                vector_value_out_2[8u] = now & 0xff;
                vector_value_out_2[9u] = (now >> 8) & 0xff;
                vector_value_out_2[10u] = (now >> 16) & 0xff;
                vector_value_out_2[11u] = (now >> 24) & 0xff;
                vector_value_out_2[12u] = (now >> 32) & 0xff;
                vector_value_out_2[13u] = (now >> 40) & 0xff;
                vector_value_out_2[14u] = (now >> 48) & 0xff;
                vector_value_out_2[15u] = (now >> 56) & 0xff;

                // 2058
                // 2059
                // 2060
                if ((now - vector_value_out_2[8ul]) < 6000000000000000ul) {

                  // 2058
                  // 2059
                  if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul) {

                    // 2058
                    if ((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length) {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    }

                    // 2059
                    else {
                      vector_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 2060
                  else {
                    vector_return(vector_4, map_value_out_2, vector_value_out_2);
                    return 1;
                  } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 2061
                else {
                  vector_return(vector_4, map_value_out_2, vector_value_out_2);
                  return 1;
                } // !((now - vector_value_out_2[8ul]) < 6000000000000000ul)

              } // !(0u == map_has_this_key__1808)

            } // !((now - vector_value_out_1[8ul]) < 6000000000000000ul)

          } // !(0u == map_has_this_key__1518)

        } // !((now - vector_value_out[8ul]) < 6000000000000000ul)

      } // !(0u == map_has_this_key__68)

    } // !(0u != device)

  }

  // 2062
  else {
    // dropping
    return device;
  } // !((8u == ether_header_1->ether_type) & (20ul <= (4294967282u + packet_length)))

}

