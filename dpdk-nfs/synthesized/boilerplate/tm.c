#include <linux/limits.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>

#include <netinet/in.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

/**********************************************
 *
 *                   LIBVIG
 *
 **********************************************/

struct tcpudp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
} __attribute__((__packed__));

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

static int find_key(int* busybits, void** keyps,
                                 unsigned* k_hashes, int* chns, void* keyp,
                                 map_keys_equality* eq, unsigned key_hash,
                                 unsigned capacity) {
  unsigned start = loop(key_hash, capacity);
  unsigned i = 0;
  for (; i < capacity; ++i)  {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    unsigned kh = k_hashes[index];
    int chn = chns[index];
    void* kp = keyps[index];
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

static unsigned find_key_remove_chain(
    int* busybits, void** keyps, unsigned* k_hashes, int* chns, void* keyp,
    map_keys_equality* eq, unsigned key_hash, unsigned capacity,
    void** keyp_out) {
  unsigned i = 0;
  unsigned start = loop(key_hash, capacity);
  
  for (; i < capacity; ++i) {
    unsigned index = loop(start + i, capacity);
    int bb = busybits[index];
    unsigned kh = k_hashes[index];
    int chn = chns[index];
    void* kp = keyps[index];
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

static unsigned find_empty(int* busybits, int* chns,
                                        unsigned start, unsigned capacity) {
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

void map_impl_init(int* busybits, map_keys_equality* eq,
                                void** keyps, unsigned* khs, int* chns,
                                int* vals, unsigned capacity) {
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

int map_impl_get(int* busybits, void** keyps, unsigned* k_hashes,
                              int* chns, int* values, void* keyp,
                              map_keys_equality* eq, unsigned hash, int* value,
                              unsigned capacity) {
  int index =
      find_key(busybits, keyps, k_hashes, chns, keyp, eq, hash, capacity);
  if (-1 == index) {
    return 0;
  }
  
  *value = values[index];
  return 1;
}

void map_impl_put(int* busybits, void** keyps, unsigned* k_hashes,
                               int* chns, int* values, void* keyp,
                               unsigned hash, int value, unsigned capacity) {
  unsigned start = loop(hash, capacity);
  unsigned index = find_empty(busybits, chns, start, capacity);

  busybits[index] = 1;
  keyps[index] = keyp;
  k_hashes[index] = hash;
  values[index] = value;
}

void map_impl_erase(int* busybits, void** keyps,
                                 unsigned* k_hashes, int* chns, void* keyp,
                                 map_keys_equality* eq, unsigned hash,
                                 unsigned capacity, void** keyp_out) {
  find_key_remove_chain(busybits, keyps, k_hashes, chns, keyp, eq, hash,
                        capacity, keyp_out);
}

unsigned map_impl_size(int* busybits, unsigned capacity) {
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

typedef struct dchain_tm_cell {
  int prev;
  int next;
} __attribute__((aligned(64))) dchain_tm_cell_t;

typedef struct {
  vigor_time_t timestamp;
} __attribute__((aligned(64))) vigor_time_alligned_t;

enum DCHAIN_ENUM {
  ALLOC_LIST_HEAD = 0,
  FREE_LIST_HEAD = 1,
  INDEX_SHIFT = DCHAIN_RESERVED
};

void dchain_tm_impl_activity_init(dchain_tm_cell_t *cells, int size) {
  dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
  al_head->prev = ALLOC_LIST_HEAD;
  al_head->next = ALLOC_LIST_HEAD;
  int i = INDEX_SHIFT;

  while (i < (size + INDEX_SHIFT)) {
    dchain_tm_cell_t *current = cells + i;
    current->next = FREE_LIST_HEAD;
    current->prev = current->next;
    ++i;
  }
}

int dchain_tm_impl_activate_index(dchain_tm_cell_t *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  dchain_tm_cell_t *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  // The index is already active.
  if (lifted_next != FREE_LIST_HEAD) {
    // There is only one element allocated - no point in changing anything
    if (lifted_next == ALLOC_LIST_HEAD) {
      return 0;
    }

    // Unlink it from the middle of the "alloc" chain.
    dchain_tm_cell_t *lifted_prevp = cells + lifted_prev;
    lifted_prevp->next = lifted_next;

    dchain_tm_cell_t *lifted_nextp = cells + lifted_next;
    lifted_nextp->prev = lifted_prev;

    dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
    int al_head_prev = al_head->prev;
  }

  dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
  int al_head_prev = al_head->prev;

  // Link it at the very end - right before the special link.
  liftedp->next = ALLOC_LIST_HEAD;
  liftedp->prev = al_head_prev;

  dchain_tm_cell_t *al_head_prevp = cells + al_head_prev;
  al_head_prevp->next = lifted;

  al_head->prev = lifted;

  return 1;
}

int dchain_tm_impl_deactivate_index(dchain_tm_cell_t *cells, int index) {
  int freed = index + INDEX_SHIFT;

  dchain_tm_cell_t *freedp = cells + freed;
  int freed_prev = freedp->prev;
  int freed_next = freedp->next;

  // The index is already free.
  if (freed_next == FREE_LIST_HEAD) {
    return 0;
  }

  dchain_tm_cell_t *freed_prevp = cells + freed_prev;
  freed_prevp->next = freed_next;

  dchain_tm_cell_t *freed_nextp = cells + freed_next;
  freed_nextp->prev = freed_prev;

  freedp->next = FREE_LIST_HEAD;
  freedp->prev = freedp->next;

  return 1;
}

int dchain_tm_impl_is_index_active(dchain_tm_cell_t *cells, int index) {
  dchain_tm_cell_t *cell = cells + index + INDEX_SHIFT;
  return cell->next != FREE_LIST_HEAD;
}

void dchain_tm_impl_init(dchain_tm_cell_t *cells, int size) {
  dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
  al_head->prev = 0;
  al_head->next = 0;
  int i = INDEX_SHIFT;

  dchain_tm_cell_t *fl_head = cells + FREE_LIST_HEAD;
  fl_head->next = i;
  fl_head->prev = fl_head->next;

  while (i < (size + INDEX_SHIFT - 1)) {

    dchain_tm_cell_t *current = cells + i;
    current->next = i + 1;
    current->prev = current->next;

    ++i;
  }

  dchain_tm_cell_t *last = cells + i;
  last->next = FREE_LIST_HEAD;
  last->prev = last->next;
}

int dchain_tm_impl_allocate_new_index(dchain_tm_cell_t *cells, int *index) {
  dchain_tm_cell_t *fl_head = cells + FREE_LIST_HEAD;
  dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
  int allocated = fl_head->next;
  if (allocated == FREE_LIST_HEAD) {
    return 0;
  }

  dchain_tm_cell_t *allocp = cells + allocated;
  // Extract the link from the "empty" chain.
  fl_head->next = allocp->next;
  fl_head->prev = fl_head->next;

  // Add the link to the "new"-end "alloc" chain.
  allocp->next = ALLOC_LIST_HEAD;
  allocp->prev = al_head->prev;

  dchain_tm_cell_t *alloc_head_prevp = cells + al_head->prev;
  alloc_head_prevp->next = allocated;
  al_head->prev = allocated;

  *index = allocated - INDEX_SHIFT;
  return 1;
}

int dchain_tm_impl_free_index(dchain_tm_cell_t *cells, int index) {
  int freed = index + INDEX_SHIFT;

  dchain_tm_cell_t *freedp = cells + freed;
  int freed_prev = freedp->prev;
  int freed_next = freedp->next;

  // The index is already free.
  if (freed_next == freed_prev) {
    if (freed_prev != ALLOC_LIST_HEAD) {
      return 0;
    }
  }

  dchain_tm_cell_t *fr_head = cells + FREE_LIST_HEAD;

  dchain_tm_cell_t *freed_prevp = cells + freed_prev;
  freed_prevp->next = freed_next;

  dchain_tm_cell_t *freed_nextp = cells + freed_next;
  freed_nextp->prev = freed_prev;

  // Add the link to the "free" chain.
  freedp->next = fr_head->next;
  freedp->prev = freedp->next;

  fr_head->next = freed;
  fr_head->prev = fr_head->next;
  return 1;
}

int dchain_tm_impl_next(dchain_tm_cell_t *cells, int index, int *next) {
  dchain_tm_cell_t *cell = cells + index + INDEX_SHIFT;

  if (cell->next == ALLOC_LIST_HEAD) {
    return 0;
  }

  *next = cell->next - INDEX_SHIFT;
  return 1;
}

int dchain_tm_impl_get_oldest_index(dchain_tm_cell_t *cells, int *index) {
  dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
  // No allocated indexes.
  if (al_head->next == al_head->prev) {
    if (al_head->next == ALLOC_LIST_HEAD) {
      return 0;
    }
  }
  *index = al_head->next - INDEX_SHIFT;
  return 1;
}

int dchain_tm_impl_reposition_index(dchain_tm_cell_t *cells, int index,
                                    int new_prev_index) {
  assert(new_prev_index >= 0);
  int lifted = index + INDEX_SHIFT;

  dchain_tm_cell_t *liftedp = cells + lifted;

  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  // The index is not allocated.
  if (lifted_next == lifted_prev && lifted_next != ALLOC_LIST_HEAD) {
    return 0;
  }

  dchain_tm_cell_t *lifted_prevp = cells + lifted_prev;
  lifted_prevp->next = lifted_next;

  dchain_tm_cell_t *lifted_nextp = cells + lifted_next;
  lifted_nextp->prev = lifted_prev;

  int new_prev = new_prev_index + INDEX_SHIFT;
  dchain_tm_cell_t *new_prevp = cells + new_prev;
  int new_prev_next = new_prevp->next;

  liftedp->prev = new_prev;
  liftedp->next = new_prev_next;

  dchain_tm_cell_t *new_prev_nextp = cells + new_prev_next;

  new_prev_nextp->prev = lifted;
  new_prevp->next = lifted;

  return 1;
}

int dchain_tm_impl_rejuvenate_index(dchain_tm_cell_t *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  dchain_tm_cell_t *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  // The index is not allocated.
  if (lifted_next == lifted_prev) {
    if (lifted_next != ALLOC_LIST_HEAD) {
      return 0;
    } else {
      return 1;
    }
  }

  dchain_tm_cell_t *lifted_prevp = cells + lifted_prev;
  lifted_prevp->next = lifted_next;

  dchain_tm_cell_t *lifted_nextp = cells + lifted_next;
  lifted_nextp->prev = lifted_prev;

  dchain_tm_cell_t *al_head = cells + ALLOC_LIST_HEAD;
  int al_head_prev = al_head->prev;

  // Link it at the very end - right before the special link.
  liftedp->next = ALLOC_LIST_HEAD;
  liftedp->prev = al_head_prev;

  dchain_tm_cell_t *al_head_prevp = cells + al_head_prev;
  al_head_prevp->next = lifted;
  al_head->prev = lifted;
  return 1;
}

int dchain_tm_impl_is_index_allocated(dchain_tm_cell_t *cells, int index) {
  int lifted = index + INDEX_SHIFT;

  dchain_tm_cell_t *liftedp = cells + lifted;
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

struct DoubleChainTM {
  dchain_tm_cell_t *cells[RTE_MAX_LCORE];
  dchain_tm_cell_t *active_cells[RTE_MAX_LCORE];
  vigor_time_alligned_t *timestamps[RTE_MAX_LCORE];
  int range;
};

typedef struct DoubleChainTM __attribute__((aligned(64))) DoubleChainTM;

int dchain_tm_allocate(int index_range, DoubleChainTM **chain_out) {

  DoubleChainTM *old_chain_out = *chain_out;
  DoubleChainTM *chain_alloc =
      (DoubleChainTM *)rte_malloc(NULL, sizeof(DoubleChainTM), 64);
  if (chain_alloc == NULL) return 0;
  *chain_out = (DoubleChainTM *)chain_alloc;

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    dchain_tm_cell_t *cells_alloc = (dchain_tm_cell_t *)rte_malloc(
        NULL, sizeof(dchain_tm_cell_t) * (index_range + DCHAIN_RESERVED), 64);
    if (cells_alloc == NULL) {
      rte_free(chain_alloc);
      *chain_out = old_chain_out;
      return 0;
    }
    (*chain_out)->cells[lcore_id] = cells_alloc;

    dchain_tm_cell_t *active_cells_alloc = (dchain_tm_cell_t *)rte_malloc(
        NULL, sizeof(dchain_tm_cell_t) * (index_range + DCHAIN_RESERVED), 64);
    if (active_cells_alloc == NULL) {
      rte_free((void *)cells_alloc);
      rte_free(chain_alloc);
      *chain_out = old_chain_out;
      return 0;
    }
    (*chain_out)->active_cells[lcore_id] = active_cells_alloc;
    dchain_tm_impl_activity_init((*chain_out)->active_cells[lcore_id],
                                 index_range);

    vigor_time_alligned_t *timestamps_alloc =
        (vigor_time_alligned_t *)rte_zmalloc(
            NULL, sizeof(vigor_time_alligned_t) * (index_range), 64);
    if (timestamps_alloc == NULL) {
      rte_free((void *)cells_alloc);
      rte_free((void *)active_cells_alloc);
      rte_free(chain_alloc);
      *chain_out = old_chain_out;
      return 0;
    }
    for (int i = 0; i < index_range; i++) {
      timestamps_alloc[i].timestamp = -1;
    }
    (*chain_out)->range = index_range;
    (*chain_out)->timestamps[lcore_id] = timestamps_alloc;

    dchain_tm_impl_init((*chain_out)->cells[lcore_id], index_range);
  }

  return 1;
}

int dchain_tm_allocate_new_index(DoubleChainTM *chain, int *index_out,
                                 vigor_time_t time) {
  int ret = -1;
  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    int new_ret =
        dchain_tm_impl_allocate_new_index(chain->cells[lcore_id], index_out);
    ret = new_ret;
    if (new_ret) {
      chain->timestamps[lcore_id][*index_out].timestamp = time;
    }
  }

  if (ret) {
    lcore_id = rte_lcore_id();
    dchain_tm_impl_activate_index(chain->active_cells[lcore_id], *index_out);
  }

  return ret;
}

int dchain_tm_rejuvenate_index(DoubleChainTM *chain, int index,
                               vigor_time_t time) {
  unsigned int lcore_id = rte_lcore_id();
  int ret = dchain_tm_impl_rejuvenate_index(chain->cells[lcore_id], index);
  if (ret) {
    chain->timestamps[lcore_id][index].timestamp = time;
    dchain_tm_impl_activate_index(chain->active_cells[lcore_id], index);
  }

  return ret;
}

int dchain_tm_update_timestamp(DoubleChainTM *chain, int index,
                               vigor_time_t time) {
  unsigned int lcore_id = rte_lcore_id();

  int new_prev = -1;
  int prev = index;
  int next;

  vigor_time_t prev_time = chain->timestamps[lcore_id][prev].timestamp;
  vigor_time_t next_time;

  while (dchain_tm_impl_next(chain->cells[lcore_id], prev, &next)) {
    next_time = chain->timestamps[lcore_id][next].timestamp;

    if (prev_time <= time && time <= next_time && index != prev) {
      new_prev = prev;
      break;
    }

    prev = next;
    prev_time = next_time;
  }

  int ret;

  if (new_prev == -1) {
    ret = dchain_tm_impl_rejuvenate_index(chain->cells[lcore_id], index);
  } else {
    ret = dchain_tm_impl_reposition_index(chain->cells[lcore_id], index,
                                          new_prev);
  }

  return ret;
}

int dchain_tm_is_index_allocated(DoubleChainTM *chain, int index) {
  return dchain_tm_impl_is_index_allocated(chain->cells[rte_lcore_id()], index);
}

int dchain_tm_free_index(DoubleChainTM *chain, int index) {
  int rez = -1;
  unsigned lcore_id;

  RTE_LCORE_FOREACH(lcore_id) {
    int new_rez = dchain_tm_impl_free_index(chain->cells[lcore_id], index);
    dchain_tm_impl_deactivate_index(chain->active_cells[lcore_id], index);
    rez = new_rez;
    chain->timestamps[lcore_id][index].timestamp = -1;
  }

  return rez;
}

int dchain_tm_expire_one_index(DoubleChainTM *chain, int *index_out,
                               vigor_time_t time) {
  unsigned int this_lcore_id = rte_lcore_id();

  int has_ind = dchain_tm_impl_get_oldest_index(
      chain->active_cells[this_lcore_id], index_out);

  if (has_ind && chain->timestamps[this_lcore_id][*index_out].timestamp > -1 &&
      chain->timestamps[this_lcore_id][*index_out].timestamp < time) {
    unsigned int lcore_id;
    vigor_time_t most_recent = -1;
    RTE_LCORE_FOREACH(lcore_id) {
      if (chain->timestamps[lcore_id][*index_out].timestamp > most_recent) {
        most_recent = chain->timestamps[lcore_id][*index_out].timestamp;
      }
    }

    if (most_recent >= time) {
      return dchain_tm_update_timestamp(chain, *index_out, most_recent);
    }

    return dchain_tm_free_index(chain, *index_out);
  }

  return 0;
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

#define MAX_CHT_HEIGHT 40000

int cht_tm_fill_cht(struct Vector *cht, uint32_t cht_height, uint32_t backend_capacity);
int cht_tm_find_preferred_available_backend(uint64_t hash, struct Vector *cht, struct DoubleChainTM *active_backends, uint32_t cht_height, uint32_t backend_capacity, int *chosen_backend);

static uint64_t cht_loop(uint64_t k, uint64_t capacity) {
  uint64_t g = k % capacity;
  return g;
}

int cht_tm_fill_cht(struct Vector *cht, uint32_t cht_height,
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

  // Fill the priority lists for each hash in [0, cht_height)
  for (uint32_t i = 0; i < cht_height; ++i) {
    for (uint32_t j = 0; j < backend_capacity; ++j) {
      uint32_t *value;

      uint32_t index = j * cht_height + i;
      int bucket_id = permutations[index];

      int priority = next[bucket_id];
      next[bucket_id] += 1;

      // Update the CHT
      vector_borrow(cht, (int)(backend_capacity * ((uint32_t)bucket_id) +
                               ((uint32_t)priority)),
                    (void **)&value);
      *value = j;
      vector_return(cht, (int)(backend_capacity * ((uint32_t)bucket_id) +
                               ((uint32_t)priority)),
                    (void *)value);
    }
  }

  // Free memory
  free(next);
  free(permutations);
  return 1;
}

int cht_tm_find_preferred_available_backend(
    uint64_t hash, struct Vector *cht, struct DoubleChainTM *active_backends,
    uint32_t cht_height, uint32_t backend_capacity, int *chosen_backend) {
  uint64_t start = cht_loop(hash, cht_height);
  for (uint32_t i = 0; i < backend_capacity; ++i) {
    uint64_t candidate_idx =
        start * backend_capacity +
        i;  // There was a bug, right here, untill I tried to prove this.

    uint32_t *candidate;
    vector_borrow(cht, (int)candidate_idx, (void **)&candidate);

    if (dchain_tm_is_index_allocated(active_backends, (int)*candidate)) {
      *chosen_backend = (int)*candidate;
      vector_return(cht, (int)candidate_idx, candidate);
      return 1;
    }

    vector_return(cht, (int)candidate_idx, candidate);
  }

  return 0;
}


int expire_items_single_map_tm(struct DoubleChainTM *chain,
                               struct Vector *vector, struct Map *map,
                               vigor_time_t time) {
  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    void *key;
    vector_borrow(vector, index, &key);
    map_erase(map, key, &key);
    vector_return(vector, index, key);
    ++count;
  }

  return count;
}

int expire_items_single_map_offseted_tm(struct DoubleChainTM *chain,
                                        struct Vector *vector, struct Map *map,
                                        vigor_time_t time, int offset) {
  assert(offset >= 0);

  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    void *key;
    vector_borrow(vector, index + offset, &key);
    map_erase(map, key, &key);
    vector_return(vector, index + offset, key);
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

#define expire_items_single_map_iteratively_tm expire_items_single_map_iteratively

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 5
#define SKETCH_SALTS_BANK_SIZE 64

const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE] = {
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

struct internal_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
} __attribute__((aligned(64)));

struct SketchTM {
  struct Map *clients;
  struct Vector *keys;
  struct Vector *buckets;
  struct DoubleChainTM *allocators[SKETCH_HASHES];

  uint32_t capacity;
  uint16_t threshold;

  map_key_hash *kh;
  struct internal_data internal[RTE_MAX_LCORE];
};

struct hash {
  uint32_t value;
};

struct bucket {
  uint32_t value;
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

int sketch_tm_allocate(map_key_hash *kh, uint32_t capacity, uint16_t threshold,
                       struct SketchTM **sketch_out) {
  assert(SKETCH_HASHES <= SKETCH_SALTS_BANK_SIZE);

  struct SketchTM *sketch_alloc =
      (struct SketchTM *)rte_malloc(NULL, sizeof(struct SketchTM), 0);
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
    if (dchain_tm_allocate(capacity, &((*sketch_out)->allocators[i])) == 0) {
      return 0;
    }
  }

  return 1;
}

void sketch_tm_compute_hashes(struct SketchTM *sketch, void *key) {
  unsigned int lcore_id = rte_lcore_id();

  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal[lcore_id].buckets_indexes[i] = -1;
    sketch->internal[lcore_id].present[i] = 0;
    sketch->internal[lcore_id].hashes[i] = 0;

    sketch->internal[lcore_id].hashes[i] = __builtin_ia32_crc32si(
        sketch->internal[lcore_id].hashes[i], SKETCH_SALTS[i]);
    sketch->internal[lcore_id].hashes[i] = __builtin_ia32_crc32si(
        sketch->internal[lcore_id].hashes[i], sketch->kh(key));
    sketch->internal[lcore_id].hashes[i] %= sketch->capacity;
  }
}

void sketch_tm_refresh(struct SketchTM *sketch, vigor_time_t now) {
  unsigned int lcore_id = rte_lcore_id();

  for (int i = 0; i < SKETCH_HASHES; i++) {
    map_get(sketch->clients, &sketch->internal[lcore_id].hashes[i],
            &sketch->internal[lcore_id].buckets_indexes[i]);
    dchain_tm_rejuvenate_index(sketch->allocators[i],
                               sketch->internal[lcore_id].buckets_indexes[i],
                               now);
  }
}

int sketch_tm_fetch(struct SketchTM *sketch) {
  unsigned int lcore_id = rte_lcore_id();

  int bucket_min_set = false;
  uint32_t *buckets_values[SKETCH_HASHES];
  uint32_t bucket_min = 0;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal[lcore_id].present[i] =
        map_get(sketch->clients, &sketch->internal[lcore_id].hashes[i],
                &sketch->internal[lcore_id].buckets_indexes[i]);

    if (!sketch->internal[lcore_id].present[i]) {
      continue;
    }

    int offseted =
        sketch->internal[lcore_id].buckets_indexes[i] + sketch->capacity * i;
    vector_borrow(sketch->buckets, offseted, (void **)&buckets_values[i]);

    if (!bucket_min_set || bucket_min > *buckets_values[i]) {
      bucket_min = *buckets_values[i];
      bucket_min_set = true;
    }

    vector_return(sketch->buckets, offseted, buckets_values[i]);
  }

  return bucket_min_set && bucket_min > sketch->threshold;
}

int sketch_tm_touch_buckets(struct SketchTM *sketch, vigor_time_t now) {
  unsigned int lcore_id = rte_lcore_id();

  for (int i = 0; i < SKETCH_HASHES; i++) {
    int bucket_index = -1;
    int present = map_get(sketch->clients,
                          &sketch->internal[lcore_id].hashes[i], &bucket_index);

    if (!present) {
      int allocated_client = dchain_tm_allocate_new_index(sketch->allocators[i],
                                                          &bucket_index, now);

      if (!allocated_client) {
        // Sketch size limit reached.
        return false;
      }

      int offseted = bucket_index + sketch->capacity * i;

      uint32_t *saved_hash = 0;
      uint32_t *saved_bucket = 0;

      vector_borrow(sketch->keys, offseted, (void **)&saved_hash);
      vector_borrow(sketch->buckets, offseted, (void **)&saved_bucket);

      (*saved_hash) = sketch->internal[lcore_id].hashes[i];
      (*saved_bucket) = 0;
      map_put(sketch->clients, saved_hash, bucket_index);

      vector_return(sketch->keys, offseted, saved_hash);
      vector_return(sketch->buckets, offseted, saved_bucket);

      return true;
    } else {
      dchain_tm_rejuvenate_index(sketch->allocators[i], bucket_index, now);
      uint32_t *bucket;
      int offseted = bucket_index + sketch->capacity * i;
      vector_borrow(sketch->buckets, offseted, (void **)&bucket);
      (*bucket)++;
      vector_return(sketch->buckets, offseted, bucket);
      return true;
    }
  }
}

void sketch_tm_expire(struct SketchTM *sketch, vigor_time_t time) {
  int offset = 0;
  int index = -1;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    offset = i * sketch->capacity;

    while (dchain_tm_expire_one_index(sketch->allocators[i], &index, time)) {
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

/**********************************************
 *
 *                  ETHER
 *
 **********************************************/

bool rte_ether_addr_eq(void* a, void* b) {
  struct rte_ether_addr* id1 = (struct rte_ether_addr*)a;
  struct rte_ether_addr* id2 = (struct rte_ether_addr*)b;
  
  return (id1->addr_bytes[0] == id2->addr_bytes[0])AND(id1->addr_bytes[1] ==
                                                       id2->addr_bytes[1])
      AND (id1->addr_bytes[2] == id2->addr_bytes[2])
      AND (id1->addr_bytes[3] == id2->addr_bytes[3])
      AND (id1->addr_bytes[4] == id2->addr_bytes[4])
      AND (id1->addr_bytes[5] == id2->addr_bytes[5]);
}

void rte_ether_addr_allocate(void* obj) {

  struct rte_ether_addr* id = (struct rte_ether_addr*)obj;

  id->addr_bytes[0] = 0;
  id->addr_bytes[1] = 0;
  id->addr_bytes[2] = 0;
  id->addr_bytes[3] = 0;
  id->addr_bytes[4] = 0;
  id->addr_bytes[5] = 0;
}

unsigned rte_ether_addr_hash(void* obj) {
  struct rte_ether_addr* id = (struct rte_ether_addr*)obj;

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
 *                  NF-RSS
 *
 **********************************************/

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52
#define MAX_NUM_DEVICES 32  // this is quite arbitrary...

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES];

struct lcore_conf {
  struct rte_mempool *mbuf_pool;
  uint16_t queue_id;
};

struct lcore_conf lcores_conf[RTE_MAX_LCORE];

/**********************************************
 *
 *                  NF-UTIL
 *
 **********************************************/

// rte_ether
struct rte_ether_addr;
struct rte_ether_hdr;

#define IP_MIN_SIZE_WORDS 5
#define WORD_SIZE 4

RTE_DEFINE_PER_LCORE(bool, write_attempt);
RTE_DEFINE_PER_LCORE(bool, write_state);

/**********************************************
 *
 *                  TM
 *
 **********************************************/

// TODO: CACHE_LINE_SIZE can be get using:
// > getconf LEVEL1_DCACHE_LINESIZE
// Number of processors:
// > getconf _NPROCESSORS_ONLN

//#pragma message ( "USING_TSX" )

#include <immintrin.h>  // includes avx512 now
#define _IMMINTRIN_H_INCLUDED
#include <xtestintrin.h>
#include <rtmintrin.h>
#define CACHE_LINE_SIZE 64
// TODO: use __sync_synchronize() instead
#define MEMFENCE asm volatile("MFENCE" : : : "memory")
#define PAUSE() _mm_pause()

typedef enum {
  HTM_SUCCESS = 0,
  HTM_ABORT,
  HTM_EXPLICIT,
  HTM_RETRY,
  HTM_CONFLICT,
  HTM_CAPACITY,
  HTM_DEBUG,
  HTM_NESTED,
  HTM_OTHER,
  HTM_FALLBACK
} HTM_errors_e;

#define HTM_NB_ERRORS 10
#define HTM_STATUS_TYPE register int
#define HTM_CODE_SUCCESS _XBEGIN_STARTED

#define HTM_begin(var) (var = _xbegin())
#define HTM_abort() _xabort(0)
#define HTM_named_abort(code) _xabort(code)
#define HTM_test() _xtest()
#define HTM_commit() _xend()
#define HTM_get_named(status) (status >> 24)
#define HTM_is_named(status) (status & 1)

#define HTM_ERROR_INC(status, error_array)                                  \
  ({                                                                        \
    if (status == _XBEGIN_STARTED) {                                        \
      error_array[HTM_SUCCESS] += 1;                                        \
    } else {                                                                \
      error_array[HTM_ABORT] += 1;                                          \
      int nb_errors = __builtin_popcount(status);                           \
      int tsx_error = status & 0x1F; /* only catch known aborts */          \
      do {                                                                  \
        int idx =                                                           \
            tsx_error & _XABORT_EXPLICIT                                    \
                ? ({                                                        \
                    tsx_error = tsx_error & ~_XABORT_EXPLICIT;              \
                    HTM_EXPLICIT;                                           \
                  })                                                        \
                : tsx_error & _XABORT_RETRY                                 \
                      ? ({                                                  \
                          tsx_error = tsx_error & ~_XABORT_RETRY;           \
                          HTM_RETRY;                                        \
                        })                                                  \
                      : tsx_error & _XABORT_CONFLICT                        \
                            ? ({                                            \
                                tsx_error = tsx_error & ~_XABORT_CONFLICT;  \
                                HTM_CONFLICT;                               \
                              })                                            \
                            : tsx_error & _XABORT_CAPACITY                  \
                                  ? ({                                      \
                                      tsx_error =                           \
                                          tsx_error & ~_XABORT_CAPACITY;    \
                                      HTM_CAPACITY;                         \
                                    })                                      \
                                  : tsx_error & _XABORT_DEBUG               \
                                        ? ({                                \
                                            tsx_error =                     \
                                                tsx_error & ~_XABORT_DEBUG; \
                                            HTM_DEBUG;                      \
                                          })                                \
                                        : HTM_OTHER;                        \
        error_array[idx] += 1;                                              \
        nb_errors--;                                                        \
      } while (nb_errors > 0);                                              \
    }                                                                       \
  })

#define CL_ALIGN __attribute__((aligned(CACHE_LINE_SIZE)))
#define CL_DISTANCE(type) CACHE_LINE_SIZE / sizeof(type)

#ifndef GRANULE_TYPE
#define GRANULE_TYPE intptr_t
#endif /* GRANULE_TYPE */

#ifndef GRANULE_P_TYPE
#define GRANULE_P_TYPE intptr_t *
#endif /* GRANULE_P_TYPE */

#ifndef GRANULE_D_TYPE
#define GRANULE_D_TYPE double
#endif /* GRANULE_D_TYPE */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HTM_SGL_INIT_BUDGET
#define HTM_SGL_INIT_BUDGET 2
#endif /* HTM_SGL_INIT_BUDGET */

typedef struct HTM_SGL_local_vars_ {
  int64_t budget;
  int64_t tid;
  int64_t status;
  uint64_t padding[5];
} __attribute__((packed)) HTM_SGL_local_vars_s;

// there is some wasted space near the SGL that can be used as read-only storate
extern void *HTM_read_only_storage1;
extern int HTM_read_only_storage1_size;
extern void *HTM_read_only_storage2;
extern int HTM_read_only_storage2_size;

extern __thread int64_t *volatile HTM_SGL_var_addr;  // points to the prev
extern __thread HTM_SGL_local_vars_s CL_ALIGN HTM_SGL_vars;
extern __thread int64_t HTM_SGL_errors[HTM_NB_ERRORS];

#define START_TRANSACTION(status) (HTM_begin(status) != HTM_CODE_SUCCESS)
#define BEFORE_TRANSACTION(tid, budget) /* empty */
#define AFTER_TRANSACTION(tid, budget)  /* empty */

/* DEBUG VERSION
#define UPDATE_BUDGET(tid, budget, status) \
    HTM_inc_status_count(status); \
    HTM_INC(status); \
        budget = HTM_update_budget(budget, status)
*/

#define UPDATE_BUDGET(tid, budget, status) \
  budget = HTM_update_budget(budget, status)

/* The HTM_SGL_update_budget also handle statistics */

#define CHECK_SGL_NOTX()                                           \
  if (__atomic_load_n(HTM_SGL_var_addr, __ATOMIC_ACQUIRE) != -1) { \
    HTM_block();                                                   \
  }
#define CHECK_SGL_HTM()                                            \
  if (__atomic_load_n(HTM_SGL_var_addr, __ATOMIC_ACQUIRE) != -1) { \
    HTM_abort();                                                   \
  }

#define AFTER_BEGIN(tid, budget, status)   /* empty */
#define BEFORE_COMMIT(tid, budget, status) /* empty */

/* DEBUG VERSION
#define COMMIT_TRANSACTION(tid, budget, status) \
    HTM_commit(); \
    HTM_inc_status_count(status); \
    HTM_INC(status)
*/

#define COMMIT_TRANSACTION(tid, budget, status) \
  HTM_commit(); /* Commits and updates some statistics after */

#define ENTER_SGL(tid) HTM_enter_fallback()
#define EXIT_SGL(tid) HTM_exit_fallback()
#define AFTER_ABORT(tid, budget, status) /* empty */

#define BEFORE_HTM_BEGIN(tid, budget) /* empty */
#define AFTER_HTM_BEGIN(tid, budget)  /* empty */
#define BEFORE_SGL_BEGIN(tid)         /* empty */
#define AFTER_SGL_BEGIN(tid)          /* empty */

#define BEFORE_HTM_COMMIT(tid, budget) /* empty */
#define AFTER_HTM_COMMIT(tid, budget)  /* empty */
#define BEFORE_SGL_COMMIT(tid)         /* empty */
#define AFTER_SGL_COMMIT(tid)          /* empty */

#define BEFORE_CHECK_BUDGET(budget) /* empty */
// called within HTM_update_budget
#define HTM_UPDATE_BUDGET(budget, status) (budget - 1)

#define ENTER_HTM_COND(tid, budget) budget > 0
#define IN_TRANSACTION(tid, budget, status) HTM_test()

// #################################
// Called within the API
#define HTM_INIT()      /* empty */
#define HTM_EXIT()      /* empty */
#define HTM_THR_INIT()  /* empty */
#define HTM_THR_EXIT()  /* empty */
#define HTM_INC(status) /* Use this to construct side statistics */
// #################################

#define HTM_SGL_budget HTM_SGL_vars.budget
#define HTM_SGL_status HTM_SGL_vars.status
#define HTM_SGL_tid HTM_SGL_vars.tid

#define HTM_SGL_begin()                                                \
  {                                                                    \
    HTM_SGL_budget = HTM_SGL_INIT_BUDGET; /* HTM_get_budget(); */      \
    BEFORE_TRANSACTION(HTM_SGL_tid, HTM_SGL_budget);                   \
    while (1) {                                                        \
      BEFORE_CHECK_BUDGET(HTM_SGL_budget);                             \
      if (ENTER_HTM_COND(HTM_SGL_tid, HTM_SGL_budget)) {               \
        CHECK_SGL_NOTX();                                              \
        BEFORE_HTM_BEGIN(HTM_SGL_tid, HTM_SGL_budget);                 \
        if (START_TRANSACTION(HTM_SGL_status)) {                       \
          UPDATE_BUDGET(HTM_SGL_tid, HTM_SGL_budget, HTM_SGL_status);  \
          AFTER_ABORT(HTM_SGL_tid, HTM_SGL_budget, HTM_SGL_status);    \
          continue;                                                    \
        }                                                              \
        CHECK_SGL_HTM();                                               \
        AFTER_HTM_BEGIN(HTM_SGL_tid, HTM_SGL_budget);                  \
      } else {                                                         \
        /*printf("BEGIN CONFLICT LIMIT REACHED %ld\n", HTM_SGL_tid);*/ \
        BEFORE_SGL_BEGIN(HTM_SGL_tid);                                 \
        ENTER_SGL(HTM_SGL_tid);                                        \
        AFTER_SGL_BEGIN(HTM_SGL_tid);                                  \
      }                                                                \
      AFTER_BEGIN(HTM_SGL_tid, HTM_SGL_budget, HTM_SGL_status);        \
      break; /* delete when using longjmp */                           \
    }                                                                  \
  }
//
#define HTM_SGL_commit()                                               \
  {                                                                    \
    BEFORE_COMMIT(HTM_SGL_tid, HTM_SGL_budget, HTM_SGL_status);        \
    if (IN_TRANSACTION(HTM_SGL_tid, HTM_SGL_budget, HTM_SGL_status)) { \
      BEFORE_HTM_COMMIT(HTM_SGL_tid, HTM_SGL_budget);                  \
      COMMIT_TRANSACTION(HTM_SGL_tid, HTM_SGL_budget, HTM_SGL_status); \
      AFTER_HTM_COMMIT(HTM_SGL_tid, HTM_SGL_budget);                   \
    } else {                                                           \
      /*printf("COMMIT CONFLICT LIMIT REACHED %ld\n", HTM_SGL_tid);*/  \
      BEFORE_SGL_COMMIT(HTM_SGL_tid);                                  \
      EXIT_SGL(HTM_SGL_tid);                                           \
      AFTER_SGL_COMMIT(HTM_SGL_tid);                                   \
    }                                                                  \
    AFTER_TRANSACTION(HTM_SGL_tid, HTM_SGL_budget);                    \
  }

#define HTM_SGL_before_write(addr, val) /* empty */
#define HTM_SGL_after_write(addr, val)  /* empty */

#define HTM_SGL_write(addr, val)     \
  ({                                 \
    HTM_SGL_before_write(addr, val); \
    *((GRANULE_TYPE *)addr) = val;   \
    HTM_SGL_after_write(addr, val);  \
    val;                             \
  })

#define HTM_SGL_write_D(addr, val)           \
  ({                                         \
    GRANULE_TYPE g = CONVERT_GRANULE_D(val); \
    HTM_SGL_write((GRANULE_TYPE *)addr, g);  \
    val;                                     \
  })

#define HTM_SGL_write_P(addr, val)                                    \
  ({                                                                  \
    GRANULE_TYPE g = (GRANULE_TYPE)val; /* works for pointers only */ \
    HTM_SGL_write((GRANULE_TYPE *)addr, g);                           \
    val;                                                              \
  })

#define HTM_SGL_before_read(addr) /* empty */

#define HTM_SGL_read(addr)     \
  ({                           \
    HTM_SGL_before_read(addr); \
    *((GRANULE_TYPE *)addr);   \
  })

#define HTM_SGL_read_P(addr)   \
  ({                           \
    HTM_SGL_before_read(addr); \
    *((GRANULE_P_TYPE *)addr); \
  })

#define HTM_SGL_read_D(addr)   \
  ({                           \
    HTM_SGL_before_read(addr); \
    *((GRANULE_D_TYPE *)addr); \
  })

/* TODO: persistency assumes an identifier */
#define HTM_SGL_alloc(size) malloc(size)
#define HTM_SGL_free(pool) free(pool)

// Exposed API
#define HTM_init(nb_threads) HTM_init_(HTM_SGL_INIT_BUDGET, nb_threads)
void HTM_init_(int init_budget, int nb_threads);
void HTM_exit();
int HTM_thr_init(int);  // pass -1 to get an id
void HTM_thr_exit();
void HTM_block();

// int HTM_update_budget(int budget, HTM_STATUS_TYPE status);
#define HTM_update_budget(budget, status) HTM_UPDATE_BUDGET(budget, status)
void HTM_enter_fallback();
void HTM_exit_fallback();

void HTM_inc_status_count(int status_code);
int HTM_get_nb_threads();
int HTM_get_tid();

// Getter and Setter for the initial budget
int HTM_get_budget();
void HTM_set_budget(int budget);

void HTM_set_is_record(int is_rec);
int HTM_get_is_record();
/**
 * @accum : int[nb_threads][HTM_NB_ERRORS]
 */
long HTM_get_status_count(int status_code, long **accum);
void HTM_reset_status_count();

#ifdef __cplusplus
}
#endif

#define LOCK(mtx)                                   \
  while (!__sync_bool_compare_and_swap(&mtx, 0, 1)) \
  PAUSE()                                           \
      //

#define UNLOCK(mtx) \
  mtx = 0;          \
  __sync_synchronize()  //

// using namespace std;

#define SGL_SIZE 128
#define SGL_POS 16

static volatile int64_t CL_ALIGN HTM_SGL_var[SGL_SIZE] = {-1};
/* extern */ __thread int64_t *volatile HTM_SGL_var_addr =
    (int64_t * volatile) & (HTM_SGL_var[SGL_POS]);
/* extern */ __thread CL_ALIGN HTM_SGL_local_vars_s HTM_SGL_vars;
/* extern */ __thread int64_t HTM_SGL_errors[HTM_NB_ERRORS];

/* extern */ void *HTM_read_only_storage1 = (void *)&(HTM_SGL_var[0]);
/* extern */ int HTM_read_only_storage1_size = SGL_POS * sizeof(int64_t);
/* extern */ void *HTM_read_only_storage2 = (void *)&(HTM_SGL_var[SGL_POS + 1]);
/* extern */ int HTM_read_only_storage2_size =
    (SGL_SIZE - SGL_POS - 1) * sizeof(int64_t);

static /* mutex */ int mtx;
static int init_budget = HTM_SGL_INIT_BUDGET;
static int threads;
static int thr_counter;

static __thread int is_record;
static __thread int tid = -1;

void HTM_init_(int init_budget, int nb_threads) {
  init_budget = HTM_SGL_INIT_BUDGET;
  threads = nb_threads;
  HTM_SGL_var[SGL_POS] = -1;
  HTM_SGL_var_addr = (int64_t * volatile) & (HTM_SGL_var[SGL_POS]);
  HTM_INIT();
}

void HTM_exit() { HTM_EXIT(); }

int HTM_thr_init(int reqTID) {
  if (tid != -1) return tid;  // TODO
  LOCK(mtx);                  // mtx.lock();
  if (reqTID != -1) {
    tid = reqTID;
    HTM_SGL_tid = reqTID;
  } else {
    tid = thr_counter++;
    HTM_SGL_tid = tid;
  }
  HTM_SGL_var_addr = (int64_t * volatile) & (HTM_SGL_var[SGL_POS]);
  HTM_THR_INIT();
  UNLOCK(mtx);  // mtx.unlock();
  return tid;
}

void HTM_thr_exit() {
  LOCK(mtx);  // mtx.lock();
  --thr_counter;
  HTM_THR_EXIT();
  UNLOCK(mtx);  // mtx.unlock();
}

int HTM_get_budget() { return init_budget; }
void HTM_set_budget(int _budget) { init_budget = _budget; }

void HTM_enter_fallback() {
  // mtx.lock();
  while (__atomic_load_n(HTM_SGL_var_addr, __ATOMIC_ACQUIRE) != tid) {
    while (__atomic_load_n(HTM_SGL_var_addr, __ATOMIC_ACQUIRE) != -1) {
      PAUSE();
    }
    __sync_val_compare_and_swap(HTM_SGL_var_addr, -1, tid);
  }

  // HTM_SGL_var = 1;
  // __sync_synchronize();
  HTM_SGL_errors[HTM_FALLBACK]++;
}

void HTM_exit_fallback() {
  // __sync_val_compare_and_swap(&HTM_SGL_var, 1, 0);
  // __asm__ __volatile__("mfence" ::: "memory");
  __atomic_store_n(HTM_SGL_var_addr, -1, __ATOMIC_RELEASE);
  // mtx.unlock();
}

void HTM_block() {
  while (__atomic_load_n(HTM_SGL_var_addr, __ATOMIC_ACQUIRE) != -1) {
    PAUSE();
  }

  // mtx.lock();
  // mtx.unlock();
}

void HTM_inc_status_count(int status_code) {
  if (is_record) {
    HTM_ERROR_INC(status_code, HTM_SGL_errors);
  }
}

// int HTM_update_budget(int budget, HTM_STATUS_TYPE status)
// {
//   int res = 0;
//   // HTM_inc_status_count(status);
//   res = HTM_UPDATE_BUDGET(budget, status);
//   return res;
// }

long HTM_get_status_count(int status_code, long **accum) {
  long res = 0;
  res = HTM_SGL_errors[status_code];
  if (accum != NULL) {
    accum[tid][status_code] = HTM_SGL_errors[status_code];
  }
  return res;
}

void HTM_reset_status_count() {
  int i, j;
  for (i = 0; i < HTM_NB_ERRORS; ++i) {
    HTM_SGL_errors[i] = 0;
  }
}

int HTM_get_nb_threads() { return threads; }
int HTM_get_tid() { return tid; }

void HTM_set_is_record(int is_rec) { is_record = is_rec; }
int HTM_get_is_record() { return is_record; }

#define RETA_CONF_SIZE (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

typedef struct {
  uint16_t tables[RTE_MAX_LCORE][ETH_RSS_RETA_SIZE_512];
  bool set;
} retas_t;

retas_t retas_per_device[MAX_NUM_DEVICES];

void init_retas();

void set_reta(uint16_t device) {
  unsigned lcores = rte_lcore_count();

  if (lcores <= 1 || !retas_per_device[device].set) {
    return;
  }

  struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(device, &dev_info);

  /* RETA setting */
  memset(reta_conf, 0, sizeof(reta_conf));

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
    reta_conf[bucket / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
  }

  for (uint16_t bucket = 0; bucket < dev_info.reta_size; bucket++) {
    uint32_t reta_id = bucket / RTE_RETA_GROUP_SIZE;
    uint32_t reta_pos = bucket % RTE_RETA_GROUP_SIZE;
    reta_conf[reta_id].reta[reta_pos] =
        retas_per_device[device].tables[lcores - 2][bucket];
  }

  /* RETA update */
  rte_eth_dev_rss_reta_update(device, reta_conf, dev_info.reta_size);
}

/**********************************************
 *
 *                  NF
 *
 **********************************************/

bool nf_init(void);
int nf_process(uint16_t device, uint8_t *buffer, uint16_t packet_length,
               vigor_time_t now);

#define FLOOD_FRAME ((uint16_t) - 1)

// Unverified support for batching, useful for performance comparisons
#define VIGOR_BATCH_SIZE 32

// Do the opposite: we want batching!
static const uint16_t RX_QUEUE_SIZE = 1024;
static const uint16_t TX_QUEUE_SIZE = 1024;

// Buffer count for mempools
static const unsigned MEMPOOL_BUFFER_COUNT = 2048;

// Send the given packet to all devices except the packet's own
void flood(struct rte_mbuf *packet, uint16_t nb_devices, uint16_t queue_id) {
  rte_mbuf_refcnt_set(packet, nb_devices - 1);
  int total_sent = 0;
  uint16_t skip_device = packet->port;
  for (uint16_t device = 0; device < nb_devices; device++) {
    if (device != skip_device) {
      total_sent += rte_eth_tx_burst(device, queue_id, &packet, 1);
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
static int nf_init_device(uint16_t device, struct rte_mempool **mbuf_pools) {
  int retval;
  const uint16_t num_queues = rte_lcore_count();

  // device_conf passed to rte_eth_dev_configure cannot be NULL
  struct rte_eth_conf device_conf = {0};
  // device_conf.rxmode.hw_strip_crc = 1;
  device_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
  device_conf.rx_adv_conf.rss_conf = rss_conf[device];

  retval = rte_eth_dev_configure(device, num_queues, num_queues, &device_conf);
  if (retval != 0) {
    return retval;
  }

  // Allocate and set up TX queues
  for (int txq = 0; txq < num_queues; txq++) {
    retval = rte_eth_tx_queue_setup(device, txq, TX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device), NULL);
    if (retval != 0) {
      return retval;
    }
  }

  unsigned lcore_id;
  int rxq = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    // Allocate and set up RX queues
    lcores_conf[lcore_id].queue_id = rxq;
    retval = rte_eth_rx_queue_setup(device, rxq, RX_QUEUE_SIZE,
                                    rte_eth_dev_socket_id(device), NULL,
                                    mbuf_pools[rxq]);
    if (retval != 0) {
      return retval;
    }

    rxq++;
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

  set_reta(device);

  return 0;
}

static void worker_main(void) {
  const unsigned lcore_id = rte_lcore_id();
  const uint16_t queue_id = lcores_conf[lcore_id].queue_id;

  if (!nf_init()) {
    rte_exit(EXIT_FAILURE, "Error initializing NF");
  }

  printf("Core %u forwarding packets.\n", rte_lcore_id());

  if (rte_eth_dev_count_avail() != 2) {
    printf(
        "We assume there will be exactly 2 devices for our simple batching "
        "implementation.");
    exit(1);
  }
  printf("Running with batches, this code is unverified!\n");

  while (1) {
    unsigned VIGOR_DEVICES_COUNT = rte_eth_dev_count_avail();
    for (uint16_t VIGOR_DEVICE = 0; VIGOR_DEVICE < VIGOR_DEVICES_COUNT;
         VIGOR_DEVICE++) {
      struct rte_mbuf *mbufs[VIGOR_BATCH_SIZE];
      uint16_t rx_count =
          rte_eth_rx_burst(VIGOR_DEVICE, queue_id, mbufs, VIGOR_BATCH_SIZE);

      struct rte_mbuf *mbufs_to_send[VIGOR_BATCH_SIZE];
      uint16_t tx_count = 0;
      for (uint16_t n = 0; n < rx_count; n++) {
        uint8_t *data = rte_pktmbuf_mtod(mbufs[n], uint8_t *);
        vigor_time_t VIGOR_NOW = current_time();
        HTM_SGL_begin();
        uint16_t dst_device =
            nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, VIGOR_NOW);
        HTM_SGL_commit();

        if (dst_device == VIGOR_DEVICE) {
          rte_pktmbuf_free(mbufs[n]);
        } else if (dst_device == FLOOD_FRAME) {
          flood(mbufs[n], VIGOR_DEVICES_COUNT, queue_id);
        } else {  // includes flood when 2 devices, which is equivalent to just
                  // a
                  // send
          mbufs_to_send[tx_count] = mbufs[n];
          tx_count++;
        }
      }

      uint16_t sent_count =
          rte_eth_tx_burst(1 - VIGOR_DEVICE, queue_id, mbufs_to_send, tx_count);
      for (uint16_t n = sent_count; n < tx_count; n++) {
        rte_pktmbuf_free(mbufs[n]);  // should not happen, but we're in the
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

  init_retas();

  char MBUF_POOL_NAME[20];
  struct rte_mempool **mbuf_pools;
  mbuf_pools = (struct rte_mempool **)rte_malloc(
      NULL, sizeof(struct rte_mempool *) * rte_lcore_count(), 64);

  HTM_init(rte_lcore_count());

  unsigned lcore_id;
  unsigned lcore_idx = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    sprintf(MBUF_POOL_NAME, "MEMORY_POOL_%u", lcore_idx);

    mbuf_pools[lcore_idx] =
        rte_pktmbuf_pool_create(MBUF_POOL_NAME,                     // name
                                MEMPOOL_BUFFER_COUNT * nb_devices,  // #elements
                                MBUF_CACHE_SIZE,  // cache size (per-lcore)
                                0,  // application private area size
                                RTE_MBUF_DEFAULT_BUF_SIZE,  // data buffer size
                                rte_socket_id()             // socket ID
                                );

    if (mbuf_pools[lcore_idx] == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
               rte_strerror(rte_errno));
    }

    lcore_idx++;
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    ret = nf_init_device(device, mbuf_pools);
    if (ret == 0) {
      printf("Initialized device %" PRIu16 ".\n", device);
    } else {
      rte_exit(EXIT_FAILURE, "Cannot init device %" PRIu16 ": %d", device, ret);
    }
  }

  RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    rte_eal_remote_launch((lcore_function_t *)worker_main, NULL, lcore_id);
  }

  worker_main();

  return 0;
}
