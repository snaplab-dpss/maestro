#ifndef _DOUBLE_MAP_LOCKS_H_INCLUDED_

#include "../verified/map-util.h"

#include <stdint.h>

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

typedef void uq_value_copy(char *dst, void *src);
typedef void dmap_locks_extract_keys(void *vp, void **kpp1, void **kpp2);
typedef void dmap_locks_pack_keys(void *vp, void *kp1, void *kp2);
typedef void uq_value_destr(void *vp);

struct DoubleMapLocks {
  int value_size;

  uq_value_copy* cpy;
  uq_value_destr* dstr;

  uint8_t *values;

  int *bbs_a;
  void **kps_a;
  unsigned *khs_a;
  int *chns_a;
  int *inds_a;
  map_keys_equality *eq_a;
  map_key_hash *hsh_a;

  int *bbs_b;
  void **kps_b;
  unsigned *khs_b;
  int *chns_b;
  int *inds_b;
  map_keys_equality *eq_b;
  map_key_hash *hsh_b;

  dmap_locks_extract_keys *exk;
  dmap_locks_pack_keys *pk;

  unsigned n_vals;
  unsigned capacity;
  unsigned keys_capacity;
};

int dmap_locks_allocate(map_keys_equality *eq_a, map_key_hash *hsh_a,
                  map_keys_equality *eq_b, map_key_hash *hsh_b, int value_size,
                  uq_value_copy *v_cpy, uq_value_destr *v_destr,
                  dmap_locks_extract_keys *dexk, dmap_locks_pack_keys *dpk,
                  unsigned capacity, unsigned keys_capacity,
                  struct DoubleMapLocks **map_out);

int dmap_locks_get_a(struct DoubleMapLocks *map, void *key, int *index);
int dmap_locks_get_b(struct DoubleMapLocks *map, void *key, int *index);
int dmap_locks_put(struct DoubleMapLocks *map, void *value, int index);
void dmap_locks_get_value(struct DoubleMapLocks *map, int index, void *value_out);
int dmap_locks_erase(struct DoubleMapLocks *map, int index);
unsigned dmap_locks_size(struct DoubleMapLocks *map);

#endif
