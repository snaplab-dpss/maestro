#include "double-map-locks.h"

#ifdef CAPACITY_POW2
#include "../verified/map-impl-pow2.h"
#else
#include "../verified/map-impl.h"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#ifndef NULL
#endif

#include <rte_malloc.h>
#include <rte_lcore.h>

int dmap_locks_allocate(map_keys_equality *eq_a, map_key_hash *hsh_a,
                        map_keys_equality *eq_b, map_key_hash *hsh_b,
                        int value_size, uq_value_copy *v_cpy,
                        uq_value_destr *v_destr, dmap_locks_extract_keys *dexk,
                        dmap_locks_pack_keys *dpk, unsigned capacity,
                        unsigned keys_capacity,
                        struct DoubleMapLocks **map_out) {
#ifdef CAPACITY_POW2
  if (keys_capacity == 0 || (keys_capacity & (keys_capacity - 1)) != 0) {
    return 0;
  }
#else
#endif
  struct DoubleMapLocks *old_map_val = *map_out;
  struct DoubleMapLocks *map_alloc = (struct DoubleMapLocks *)rte_malloc(
      NULL, sizeof(struct DoubleMapLocks), 64);
  if (map_alloc == NULL) return 0;
  *map_out = (struct DoubleMapLocks *)map_alloc;
  uint8_t *vals_alloc =
      (uint8_t *)rte_malloc(NULL, (uint32_t)value_size * capacity, 64);
  if (vals_alloc == NULL) {
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->values = vals_alloc;
  int *bbs_a_alloc =
      (int *)rte_malloc(NULL, sizeof(int) * (int)keys_capacity, 64);
  if (bbs_a_alloc == NULL) {
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->bbs_a = bbs_a_alloc;
  void **kps_a_alloc =
      (void **)rte_malloc(NULL, sizeof(void *) * (int)keys_capacity, 64);
  if (kps_a_alloc == NULL) {
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->kps_a = kps_a_alloc;
  unsigned *khs_a_alloc =
      (unsigned *)rte_malloc(NULL, sizeof(unsigned) * (int)keys_capacity, 64);
  if (khs_a_alloc == NULL) {
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->khs_a = khs_a_alloc;
  int *chns_a_alloc =
      (int *)rte_malloc(NULL, sizeof(int) * (int)keys_capacity, 64);
  if (chns_a_alloc == NULL) {
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->chns_a = chns_a_alloc;
  int *inds_a_alloc =
      (int *)rte_malloc(NULL, sizeof(int) * (int)keys_capacity, 64);
  if (inds_a_alloc == NULL) {
    rte_free(chns_a_alloc);
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->inds_a = inds_a_alloc;
  int *bbs_b_alloc =
      (int *)rte_malloc(NULL, sizeof(int) * (int)keys_capacity, 64);
  if (bbs_b_alloc == NULL) {
    rte_free(inds_a_alloc);
    rte_free(chns_a_alloc);
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->bbs_b = bbs_b_alloc;
  void **kps_b_alloc =
      (void **)rte_malloc(NULL, sizeof(void *) * (int)keys_capacity, 64);
  if (kps_b_alloc == NULL) {
    rte_free(bbs_b_alloc);
    rte_free(inds_a_alloc);
    rte_free(chns_a_alloc);
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->kps_b = kps_b_alloc;
  unsigned *khs_b_alloc =
      (unsigned *)rte_malloc(NULL, sizeof(unsigned) * (int)keys_capacity, 64);
  if (khs_b_alloc == NULL) {
    rte_free(kps_b_alloc);
    rte_free(bbs_b_alloc);
    rte_free(inds_a_alloc);
    rte_free(chns_a_alloc);
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->khs_b = khs_b_alloc;
  int *inds_b_alloc =
      (int *)rte_malloc(NULL, sizeof(int) * (int)keys_capacity, 64);
  if (inds_b_alloc == NULL) {
    rte_free(khs_b_alloc);
    rte_free(kps_b_alloc);
    rte_free(bbs_b_alloc);
    rte_free(inds_a_alloc);
    rte_free(chns_a_alloc);
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->inds_b = inds_b_alloc;
  int *chns_b_alloc =
      (int *)rte_malloc(NULL, sizeof(int) * (int)keys_capacity, 64);
  if (chns_b_alloc == NULL) {
    rte_free(inds_b_alloc);
    rte_free(khs_b_alloc);
    rte_free(kps_b_alloc);
    rte_free(bbs_b_alloc);
    rte_free(inds_a_alloc);
    rte_free(chns_a_alloc);
    rte_free(khs_a_alloc);
    rte_free(kps_a_alloc);
    rte_free(bbs_a_alloc);
    rte_free(vals_alloc);
    rte_free(map_alloc);
    *map_out = old_map_val;
    return 0;
  }
  (*map_out)->chns_b = chns_b_alloc;
  (*map_out)->eq_a = eq_a;
  (*map_out)->hsh_a = hsh_a;
  (*map_out)->eq_b = eq_b;
  (*map_out)->hsh_b = hsh_b;
  (*map_out)->value_size = value_size;
  (*map_out)->cpy = v_cpy;
  (*map_out)->dstr = v_destr;
  (*map_out)->exk = dexk;
  (*map_out)->pk = dpk;
  (*map_out)->capacity = capacity;
  (*map_out)->keys_capacity = keys_capacity;
  map_impl_init((*map_out)->bbs_a, (*map_out)->eq_a, (*map_out)->kps_a,
                (*map_out)->khs_a, (*map_out)->chns_a, (*map_out)->inds_a,
                (*map_out)->keys_capacity);
  map_impl_init((*map_out)->bbs_b, (*map_out)->eq_b, (*map_out)->kps_b,
                (*map_out)->khs_b, (*map_out)->chns_b, (*map_out)->inds_b,
                (*map_out)->keys_capacity);
  (*map_out)->n_vals = 0;
  return 1;
}

int dmap_locks_get_a(struct DoubleMapLocks *map, void *key, int *index) {
  map_key_hash *hsh_a = map->hsh_a;
  unsigned hash = hsh_a(key);
  int rez =
      map_impl_get(map->bbs_a, map->kps_a, map->khs_a, map->chns_a, map->inds_a,
                   key, map->eq_a, hash, index, map->keys_capacity);
  return rez;
}

int dmap_locks_get_b(struct DoubleMapLocks *map, void *key, int *index) {
  map_key_hash *hsh_b = map->hsh_b;
  unsigned hash = hsh_b(key);
  return map_impl_get(map->bbs_b, map->kps_b, map->khs_b, map->chns_b,
                      map->inds_b, key, map->eq_b, hash, index,
                      map->keys_capacity);
}

int dmap_locks_put(struct DoubleMapLocks *map, void *value, int index) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return 1;
  }

  void *key_a = 0;
  void *key_b = 0;
  void *my_value = map->values + index * map->value_size;
  uq_value_copy *cpy = map->cpy;
  cpy((char *)my_value, value);
  dmap_locks_extract_keys *exk = map->exk;
  exk(my_value, &key_a, &key_b);
  map_key_hash *hsh_a = map->hsh_a;
  unsigned hash1 = hsh_a(key_a);
  map_impl_put(map->bbs_a, map->kps_a, map->khs_a, map->chns_a, map->inds_a,
               key_a, hash1, index, map->keys_capacity);
  map_key_hash *hsh_b = map->hsh_b;
  unsigned hash2 = hsh_b(key_b);
  map_impl_put(map->bbs_b, map->kps_b, map->khs_b, map->chns_b, map->inds_b,
               key_b, hash2, index, map->keys_capacity);
  ++map->n_vals;
  dmap_locks_pack_keys *pk = map->pk;
  pk(my_value, key_a, key_b);
  return 1;
}

void dmap_locks_get_value(struct DoubleMapLocks *map, int index,
                          void *value_out) {
  void *my_value = map->values + index * map->value_size;
  uq_value_copy *cpy = map->cpy;
  cpy((char *)value_out, (char *)my_value);
}

int dmap_locks_erase(struct DoubleMapLocks *map, int index) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return 1;
  }

  void *key_a = 0;
  void *out_key_a = 0;
  void *key_b = 0;
  void *out_key_b = 0;
  void *my_value = map->values + index * map->value_size;
  dmap_locks_extract_keys *exk = map->exk;
  exk(my_value, &key_a, &key_b);
  map_key_hash *hsh_a = map->hsh_a;
  unsigned hash1 = hsh_a(key_a);
  map_impl_erase(map->bbs_a, map->kps_a, map->khs_a, map->chns_a, key_a,
                 map->eq_a, hash1, map->keys_capacity, &out_key_a);
  map_key_hash *hsh_b = map->hsh_b;
  unsigned hash2 = hsh_b(key_b);
  map_impl_erase(map->bbs_b, map->kps_b, map->khs_b, map->chns_b, key_b,
                 map->eq_b, hash2, map->keys_capacity, &out_key_b);
  dmap_locks_pack_keys *pk = map->pk;
  pk(my_value, key_a, key_b);
  pk(my_value, out_key_a, out_key_b);
  uq_value_destr *dstr = map->dstr;
  dstr(my_value);
  --map->n_vals;
  return 1;
}

unsigned dmap_locks_size(struct DoubleMapLocks *map) { return map->n_vals; }
