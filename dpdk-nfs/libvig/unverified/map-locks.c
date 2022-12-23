#include <stdlib.h>
#include <stddef.h>

#include "map-locks.h"

#include <rte_malloc.h>

#ifdef CAPACITY_POW2
#include "../verified/map-impl-pow2.h"
#else
#include "../verified/map-impl.h"
#endif

struct MapLocks {
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

int map_locks_allocate(map_keys_equality *keq, map_key_hash *khash,
                       unsigned capacity, struct MapLocks **map_locks_out) {
#ifdef CAPACITY_POW2
  if (capacity == 0 || (capacity & (capacity - 1)) != 0) {
    return 0;
  }
#else
#endif
  struct MapLocks *old_map_locks_val = *map_locks_out;
  struct MapLocks *map_locks_alloc =
      (struct MapLocks *)rte_malloc(NULL, sizeof(struct MapLocks), 64);
  if (map_locks_alloc == NULL) return 0;
  *map_locks_out = (struct MapLocks *)map_locks_alloc;
  int *bbs_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (bbs_alloc == NULL) {
    rte_free(map_locks_alloc);
    *map_locks_out = old_map_locks_val;
    return 0;
  }
  (*map_locks_out)->busybits = bbs_alloc;
  void **keyps_alloc =
      (void **)rte_malloc(NULL, sizeof(void *) * (int)capacity, 64);
  if (keyps_alloc == NULL) {
    rte_free(bbs_alloc);
    rte_free(map_locks_alloc);
    *map_locks_out = old_map_locks_val;
    return 0;
  }
  (*map_locks_out)->keyps = keyps_alloc;
  unsigned *khs_alloc =
      (unsigned *)rte_malloc(NULL, sizeof(unsigned) * (int)capacity, 64);
  if (khs_alloc == NULL) {
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_locks_alloc);
    *map_locks_out = old_map_locks_val;
    return 0;
  }
  (*map_locks_out)->khs = khs_alloc;
  int *chns_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (chns_alloc == NULL) {
    rte_free(khs_alloc);
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_locks_alloc);
    *map_locks_out = old_map_locks_val;
    return 0;
  }
  (*map_locks_out)->chns = chns_alloc;
  int *vals_alloc = (int *)rte_malloc(NULL, sizeof(int) * (int)capacity, 64);
  if (vals_alloc == NULL) {
    rte_free(chns_alloc);
    rte_free(khs_alloc);
    rte_free(keyps_alloc);
    rte_free(bbs_alloc);
    rte_free(map_locks_alloc);
    *map_locks_out = old_map_locks_val;
    return 0;
  }
  (*map_locks_out)->vals = vals_alloc;
  (*map_locks_out)->capacity = capacity;
  (*map_locks_out)->size = 0;
  (*map_locks_out)->keys_eq = keq;
  (*map_locks_out)->khash = khash;
  map_impl_init((*map_locks_out)->busybits, keq, (*map_locks_out)->keyps,
                (*map_locks_out)->khs, (*map_locks_out)->chns,
                (*map_locks_out)->vals, capacity);
  return 1;
}
int map_locks_get(struct MapLocks *map, void *key, int *value_out) {
  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  return map_impl_get(map->busybits, map->keyps, map->khs, map->chns, map->vals,
                      key, map->keys_eq, hash, value_out, map->capacity);
}
void map_locks_put(struct MapLocks *map, void *key, int value) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return;
  }

  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  map_impl_put(map->busybits, map->keyps, map->khs, map->chns, map->vals, key,
               hash, value, map->capacity);
  ++map->size;
}
void map_locks_erase(struct MapLocks *map, void *key, void **trash) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return;
  }

  map_key_hash *khash = map->khash;
  unsigned hash = khash(key);
  map_impl_erase(map->busybits, map->keyps, map->khs, map->chns, key,
                 map->keys_eq, hash, map->capacity, trash);
  --map->size;
}
unsigned map_locks_size(struct MapLocks *map) { return map->size; }
