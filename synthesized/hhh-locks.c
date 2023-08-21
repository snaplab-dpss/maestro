#define _GNU_SOURCE

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

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <rte_atomic.h>
#include <rte_build_config.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_per_lcore.h>
#include <rte_thash.h>

/**********************************************
 *
 *                   LIBVIG
 *
 **********************************************/

RTE_DEFINE_PER_LCORE(bool, write_attempt);
RTE_DEFINE_PER_LCORE(bool, write_state);

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

#define CAPACITY_UPPER_LIMIT 140000

typedef unsigned map_key_hash(void *k1);
typedef bool map_keys_equality(void *k1, void *k2);

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
  if (map_locks_alloc == NULL)
    return 0;
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

struct VectorLocks;

typedef void vector_init_elem(void *elem);

struct VectorLocks {
  char *data;
  int elem_size;
  unsigned capacity;
};

int vector_locks_allocate(int elem_size, unsigned capacity,
                          vector_init_elem *init_elem,
                          struct VectorLocks **vector_out) {
  struct VectorLocks *old_vector_val = *vector_out;
  struct VectorLocks *vector_alloc =
      (struct VectorLocks *)rte_malloc(NULL, sizeof(struct VectorLocks), 64);
  if (vector_alloc == 0)
    return 0;
  *vector_out = (struct VectorLocks *)vector_alloc;
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
void vector_locks_borrow(struct VectorLocks *vector, int index,
                         void **val_out) {
  *val_out = vector->data + index * vector->elem_size;
}
void vector_locks_return(struct VectorLocks *vector, int index, void *value) {}

struct dchain_locks_cell {
  int prev;
  int next;
};

#define DCHAIN_RESERVED (2)

enum DCHAIN_ENUM {
  ALLOC_LIST_HEAD = 0,
  FREE_LIST_HEAD = 1,
  INDEX_SHIFT = DCHAIN_RESERVED
};

void dchain_locks_impl_activity_init(struct dchain_locks_cell *cells,
                                     int size) {
  struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
  al_head->prev = ALLOC_LIST_HEAD;
  al_head->next = ALLOC_LIST_HEAD;
  int i = INDEX_SHIFT;

  while (i < (size + INDEX_SHIFT)) {
    struct dchain_locks_cell *current = cells + i;
    current->next = FREE_LIST_HEAD;
    current->prev = current->next;
    ++i;
  }
}

int dchain_locks_impl_activate_index(struct dchain_locks_cell *cells,
                                     int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_locks_cell *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  // The index is already active.
  if (lifted_next != FREE_LIST_HEAD) {
    // There is only one element allocated - no point in changing anything
    if (lifted_next == ALLOC_LIST_HEAD) {
      return 0;
    }

    // Unlink it from the middle of the "alloc" chain.
    struct dchain_locks_cell *lifted_prevp = cells + lifted_prev;
    lifted_prevp->next = lifted_next;

    struct dchain_locks_cell *lifted_nextp = cells + lifted_next;
    lifted_nextp->prev = lifted_prev;

    struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
    int al_head_prev = al_head->prev;
  }

  struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
  int al_head_prev = al_head->prev;

  // Link it at the very end - right before the special link.
  liftedp->next = ALLOC_LIST_HEAD;
  liftedp->prev = al_head_prev;

  struct dchain_locks_cell *al_head_prevp = cells + al_head_prev;
  al_head_prevp->next = lifted;

  al_head->prev = lifted;

  return 1;
}

int dchain_locks_impl_deactivate_index(struct dchain_locks_cell *cells,
                                       int index) {
  int freed = index + INDEX_SHIFT;

  struct dchain_locks_cell *freedp = cells + freed;
  int freed_prev = freedp->prev;
  int freed_next = freedp->next;

  // The index is already free.
  if (freed_next == FREE_LIST_HEAD) {
    return 0;
  }

  struct dchain_locks_cell *freed_prevp = cells + freed_prev;
  freed_prevp->next = freed_next;

  struct dchain_locks_cell *freed_nextp = cells + freed_next;
  freed_nextp->prev = freed_prev;

  freedp->next = FREE_LIST_HEAD;
  freedp->prev = freedp->next;

  return 1;
}

int dchain_locks_impl_is_index_active(struct dchain_locks_cell *cells,
                                      int index) {
  struct dchain_locks_cell *cell = cells + index + INDEX_SHIFT;
  return cell->next != FREE_LIST_HEAD;
}

void dchain_locks_impl_init(struct dchain_locks_cell *cells, int size) {

  struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
  al_head->prev = 0;
  al_head->next = 0;
  int i = INDEX_SHIFT;

  struct dchain_locks_cell *fl_head = cells + FREE_LIST_HEAD;
  fl_head->next = i;
  fl_head->prev = fl_head->next;

  while (i < (size + INDEX_SHIFT - 1)) {
    struct dchain_locks_cell *current = cells + i;
    current->next = i + 1;
    current->prev = current->next;

    ++i;
  }

  struct dchain_locks_cell *last = cells + i;
  last->next = FREE_LIST_HEAD;
  last->prev = last->next;
}

int dchain_locks_impl_allocate_new_index(struct dchain_locks_cell *cells,
                                         int *index) {
  struct dchain_locks_cell *fl_head = cells + FREE_LIST_HEAD;
  struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
  int allocated = fl_head->next;
  if (allocated == FREE_LIST_HEAD) {
    return 0;
  }

  struct dchain_locks_cell *allocp = cells + allocated;

  fl_head->next = allocp->next;
  fl_head->prev = fl_head->next;

  // Add the link to the "new"-end "alloc" chain.
  allocp->next = ALLOC_LIST_HEAD;
  allocp->prev = al_head->prev;

  struct dchain_locks_cell *alloc_head_prevp = cells + al_head->prev;
  alloc_head_prevp->next = allocated;
  al_head->prev = allocated;

  *index = allocated - INDEX_SHIFT;
  return 1;
}

int dchain_locks_impl_free_index(struct dchain_locks_cell *cells, int index) {
  int freed = index + INDEX_SHIFT;

  struct dchain_locks_cell *freedp = cells + freed;
  int freed_prev = freedp->prev;
  int freed_next = freedp->next;

  // The index is already free.
  if (freed_next == freed_prev) {
    if (freed_prev != ALLOC_LIST_HEAD) {
      return 0;
    }
  }
  struct dchain_locks_cell *fr_head = cells + FREE_LIST_HEAD;

  struct dchain_locks_cell *freed_prevp = cells + freed_prev;
  freed_prevp->next = freed_next;

  struct dchain_locks_cell *freed_nextp = cells + freed_next;
  freed_nextp->prev = freed_prev;

  // Add the link to the "free" chain.
  freedp->next = fr_head->next;
  freedp->prev = freedp->next;

  fr_head->next = freed;
  fr_head->prev = fr_head->next;
  return 1;
}

int dchain_locks_impl_next(struct dchain_locks_cell *cells, int index,
                           int *next) {
  struct dchain_locks_cell *cell = cells + index + INDEX_SHIFT;

  if (cell->next == ALLOC_LIST_HEAD) {
    return 0;
  }

  *next = cell->next - INDEX_SHIFT;
  return 1;
}

int dchain_locks_impl_get_oldest_index(struct dchain_locks_cell *cells,
                                       int *index) {
  struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
  // No allocated indexes.
  if (al_head->next == al_head->prev) {
    if (al_head->next == ALLOC_LIST_HEAD) {
      return 0;
    }
  }

  *index = al_head->next - INDEX_SHIFT;

  return 1;
}

int dchain_locks_impl_reposition_index(struct dchain_locks_cell *cells,
                                       int index, int new_prev_index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_locks_cell *liftedp = cells + lifted;

  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  // The index is not allocated.
  if (lifted_next == lifted_prev && lifted_next != ALLOC_LIST_HEAD) {
    return 0;
  }

  struct dchain_locks_cell *lifted_prevp = cells + lifted_prev;
  lifted_prevp->next = lifted_next;

  struct dchain_locks_cell *lifted_nextp = cells + lifted_next;
  lifted_nextp->prev = lifted_prev;

  int new_prev = new_prev_index + INDEX_SHIFT;
  struct dchain_locks_cell *new_prevp = cells + new_prev;
  int new_prev_next = new_prevp->next;

  liftedp->prev = new_prev;
  liftedp->next = new_prev_next;

  struct dchain_locks_cell *new_prev_nextp = cells + new_prev_next;

  new_prev_nextp->prev = lifted;
  new_prevp->next = lifted;

  return 1;
}

int dchain_locks_impl_rejuvenate_index(struct dchain_locks_cell *cells,
                                       int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_locks_cell *liftedp = cells + lifted;
  int lifted_next = liftedp->next;
  int lifted_prev = liftedp->prev;

  // The index is not allocated.
  if (lifted_next == lifted_prev) {
    if (lifted_next != ALLOC_LIST_HEAD) {
      return 0;
    } else {
      // There is only one element allocated - no point in changing anything
      return 1;
    }
  }

  struct dchain_locks_cell *lifted_prevp = cells + lifted_prev;
  lifted_prevp->next = lifted_next;

  struct dchain_locks_cell *lifted_nextp = cells + lifted_next;
  lifted_nextp->prev = lifted_prev;

  struct dchain_locks_cell *al_head = cells + ALLOC_LIST_HEAD;
  int al_head_prev = al_head->prev;

  // Link it at the very end - right before the special link.
  liftedp->next = ALLOC_LIST_HEAD;
  liftedp->prev = al_head_prev;

  struct dchain_locks_cell *al_head_prevp = cells + al_head_prev;
  al_head_prevp->next = lifted;

  al_head->prev = lifted;
  return 1;
}

int dchain_locks_impl_is_index_allocated(struct dchain_locks_cell *cells,
                                         int index) {
  int lifted = index + INDEX_SHIFT;

  struct dchain_locks_cell *liftedp = cells + lifted;
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

struct DoubleChainLocks;
// Makes sure the allocator structur fits into memory, and particularly into
// 32 bit address space.
#define IRANG_LIMIT (1048576)

// kinda hacky, but makes the proof independent of vigor_time_t... sort of
#define malloc_block_time malloc_block_llongs
#define time_integer llong_integer
#define times llongs

struct DoubleChainLocks {
  struct dchain_locks_cell *cells[RTE_MAX_LCORE];
  struct dchain_locks_cell *active_cells[RTE_MAX_LCORE];
  vigor_time_t *timestamps[RTE_MAX_LCORE];
  int range;
};

int dchain_locks_allocate(int index_range,
                          struct DoubleChainLocks **chain_out) {

  struct DoubleChainLocks *old_chain_out = *chain_out;
  struct DoubleChainLocks *chain_alloc = (struct DoubleChainLocks *)rte_malloc(
      NULL, sizeof(struct DoubleChainLocks), 0);
  if (chain_alloc == NULL)
    return 0;
  *chain_out = (struct DoubleChainLocks *)chain_alloc;

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    struct dchain_locks_cell *cells_alloc =
        (struct dchain_locks_cell *)rte_malloc(
            NULL,
            sizeof(struct dchain_locks_cell) * (index_range + DCHAIN_RESERVED),
            0);
    if (cells_alloc == NULL) {
      rte_free(chain_alloc);
      *chain_out = old_chain_out;
      return 0;
    }
    (*chain_out)->cells[lcore_id] = cells_alloc;

    struct dchain_locks_cell *active_cells_alloc =
        (struct dchain_locks_cell *)rte_malloc(
            NULL,
            sizeof(struct dchain_locks_cell) * (index_range + DCHAIN_RESERVED),
            0);
    if (active_cells_alloc == NULL) {
      rte_free((void *)cells_alloc);
      rte_free(chain_alloc);
      *chain_out = old_chain_out;
      return 0;
    }
    (*chain_out)->active_cells[lcore_id] = active_cells_alloc;
    dchain_locks_impl_activity_init((*chain_out)->active_cells[lcore_id],
                                    index_range);

    vigor_time_t *timestamps_alloc = (vigor_time_t *)rte_zmalloc(
        NULL, sizeof(vigor_time_t) * (index_range), 0);
    if (timestamps_alloc == NULL) {
      rte_free((void *)cells_alloc);
      rte_free((void *)active_cells_alloc);
      rte_free(chain_alloc);
      *chain_out = old_chain_out;
      return 0;
    }
    for (int i = 0; i < index_range; i++) {
      timestamps_alloc[i] = -1;
    }
    (*chain_out)->range = index_range;
    (*chain_out)->timestamps[lcore_id] = timestamps_alloc;

    dchain_locks_impl_init((*chain_out)->cells[lcore_id], index_range);
  }

  return 1;
}

int dchain_locks_allocate_new_index(struct DoubleChainLocks *chain,
                                    int *index_out, vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return 1;
  }

  int ret = -1;
  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    int new_ret =
        dchain_locks_impl_allocate_new_index(chain->cells[lcore_id], index_out);
    ret = new_ret;
    if (new_ret) {
      chain->timestamps[lcore_id][*index_out] = time;
    }
  }

  if (ret) {
    lcore_id = rte_lcore_id();
    dchain_locks_impl_activate_index(chain->active_cells[lcore_id], *index_out);
  }

  return ret;
}

int dchain_locks_rejuvenate_index(struct DoubleChainLocks *chain, int index,
                                  vigor_time_t time) {
  unsigned int lcore_id = rte_lcore_id();
  int ret = dchain_locks_impl_rejuvenate_index(chain->cells[lcore_id], index);

  if (ret) {
    chain->timestamps[lcore_id][index] = time;
    dchain_locks_impl_activate_index(chain->active_cells[lcore_id], index);
  }

  return ret;
}

int dchain_locks_update_timestamp(struct DoubleChainLocks *chain, int index,
                                  vigor_time_t time) {
  unsigned int lcore_id = rte_lcore_id();

  int new_prev = -1;
  int prev = index;
  int next;

  vigor_time_t prev_time = chain->timestamps[lcore_id][prev];
  vigor_time_t next_time;

  while (dchain_locks_impl_next(chain->cells[lcore_id], prev, &next)) {
    next_time = chain->timestamps[lcore_id][next];

    if (prev_time <= time && time <= next_time && index != prev) {
      new_prev = prev;
      break;
    }

    prev = next;
    prev_time = next_time;
  }

  int ret;

  if (new_prev == -1) {
    ret = dchain_locks_impl_rejuvenate_index(chain->cells[lcore_id], index);
  } else {
    ret = dchain_locks_impl_reposition_index(chain->cells[lcore_id], index,
                                             new_prev);
  }

  return ret;
}

int dchain_locks_free_index(struct DoubleChainLocks *chain, int index) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return 1;
  }

  int rez = -1;
  unsigned lcore_id;

  RTE_LCORE_FOREACH(lcore_id) {
    int new_rez = dchain_locks_impl_free_index(chain->cells[lcore_id], index);
    dchain_locks_impl_deactivate_index(chain->active_cells[lcore_id], index);
    rez = new_rez;
    chain->timestamps[lcore_id][index] = -1;
  }

  return rez;
}

int dchain_locks_expire_one_index(struct DoubleChainLocks *chain,
                                  int *index_out, vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  unsigned int this_lcore_id = rte_lcore_id();

  int has_ind = dchain_locks_impl_get_oldest_index(
      chain->active_cells[this_lcore_id], index_out);

  if (has_ind && chain->timestamps[this_lcore_id][*index_out] > -1 &&
      chain->timestamps[this_lcore_id][*index_out] < time) {
    if (!*write_state_ptr) {
      *write_attempt_ptr = true;
      return 1;
    }

    unsigned int lcore_id;
    vigor_time_t most_recent = -1;
    RTE_LCORE_FOREACH(lcore_id) {
      if (chain->timestamps[lcore_id][*index_out] > most_recent) {
        most_recent = chain->timestamps[lcore_id][*index_out];
      }
    }

    if (most_recent >= time) {
      return dchain_locks_update_timestamp(chain, *index_out, most_recent);
    }

    return dchain_locks_free_index(chain, *index_out);
  }

  return 0;
}

int dchain_locks_is_index_allocated(struct DoubleChainLocks *chain, int index) {
  return dchain_locks_impl_is_index_allocated(chain->cells[rte_lcore_id()],
                                              index);
}

typedef void entry_extract_key(void *entry, void **key);
typedef void entry_pack_key(void *entry, void *key);

int expire_items_single_map_locks(struct DoubleChainLocks *chain,
                                  struct VectorLocks *vector,
                                  struct MapLocks *map, vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  int count = 0;
  int index = -1;

  while (dchain_locks_expire_one_index(chain, &index, time)) {
    if (!*write_state_ptr) {
      *write_attempt_ptr = true;
      return 1;
    }

    void *key;
    vector_locks_borrow(vector, index, &key);
    map_locks_erase(map, key, &key);
    vector_locks_return(vector, index, key);
    ++count;
  }

  return count;
}

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 4
#define SKETCH_SALTS_BANK_SIZE 64

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

struct internal_data {
  unsigned hashes[SKETCH_HASHES];
  int present[SKETCH_HASHES];
  int buckets_indexes[SKETCH_HASHES];
} __attribute__((aligned(64)));

struct SketchLocks {
  struct MapLocks *clients;
  struct VectorLocks *keys;
  struct VectorLocks *buckets;
  struct DoubleChainLocks *allocators[SKETCH_HASHES];

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

int sketch_locks_allocate(map_key_hash *kh, uint32_t capacity,
                          uint16_t threshold, struct SketchLocks **sketch_out) {
  assert(SKETCH_HASHES <= SKETCH_SALTS_BANK_SIZE);

  struct SketchLocks *sketch_alloc =
      (struct SketchLocks *)rte_malloc(NULL, sizeof(struct SketchLocks), 0);
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
  if (map_locks_allocate(hash_eq, hash_hash, total_sketch_capacity,
                         &((*sketch_out)->clients)) == 0) {
    return 0;
  }

  (*sketch_out)->keys = NULL;
  if (vector_locks_allocate(sizeof(struct hash), total_sketch_capacity,
                            hash_allocate, &((*sketch_out)->keys)) == 0) {
    return 0;
  }

  (*sketch_out)->buckets = NULL;
  if (vector_locks_allocate(sizeof(struct bucket), total_sketch_capacity,
                            bucket_allocate, &((*sketch_out)->buckets)) == 0) {
    return 0;
  }

  for (int i = 0; i < SKETCH_HASHES; i++) {
    (*sketch_out)->allocators[i] = NULL;
    if (dchain_locks_allocate(capacity, &((*sketch_out)->allocators[i])) == 0) {
      return 0;
    }
  }

  return 1;
}

void sketch_locks_compute_hashes(struct SketchLocks *sketch, void *key) {
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

void sketch_locks_refresh(struct SketchLocks *sketch, vigor_time_t now) {
  unsigned int lcore_id = rte_lcore_id();

  for (int i = 0; i < SKETCH_HASHES; i++) {
    map_locks_get(sketch->clients, &sketch->internal[lcore_id].hashes[i],
                  &sketch->internal[lcore_id].buckets_indexes[i]);
    dchain_locks_rejuvenate_index(sketch->allocators[i],
                                  sketch->internal[lcore_id].buckets_indexes[i],
                                  now);
  }
}

int sketch_locks_fetch(struct SketchLocks *sketch) {
  unsigned int lcore_id = rte_lcore_id();

  int bucket_min_set = false;
  uint32_t *buckets_values[SKETCH_HASHES];
  uint32_t bucket_min = 0;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    sketch->internal[lcore_id].present[i] =
        map_locks_get(sketch->clients, &sketch->internal[lcore_id].hashes[i],
                      &sketch->internal[lcore_id].buckets_indexes[i]);

    if (!sketch->internal[lcore_id].present[i]) {
      continue;
    }

    int offseted =
        sketch->internal[lcore_id].buckets_indexes[i] + sketch->capacity * i;
    vector_locks_borrow(sketch->buckets, offseted, (void **)&buckets_values[i]);

    if (!bucket_min_set || bucket_min > *buckets_values[i]) {
      bucket_min = *buckets_values[i];
      bucket_min_set = true;
    }

    vector_locks_return(sketch->buckets, offseted, buckets_values[i]);
  }

  return bucket_min_set && bucket_min > sketch->threshold;
}

int sketch_locks_touch_buckets(struct SketchLocks *sketch, vigor_time_t now) {
  unsigned int lcore_id = rte_lcore_id();

  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (!*write_state_ptr) {
    *write_attempt_ptr = true;
    return false;
  }

  for (int i = 0; i < SKETCH_HASHES; i++) {
    int bucket_index = -1;
    int present = map_locks_get(
        sketch->clients, &sketch->internal[lcore_id].hashes[i], &bucket_index);

    if (!present) {
      int allocated_client = dchain_locks_allocate_new_index(
          sketch->allocators[i], &bucket_index, now);

      if (!allocated_client) {
        // Sketch size limit reached.
        return false;
      }

      int offseted = bucket_index + sketch->capacity * i;

      uint32_t *saved_hash = 0;
      uint32_t *saved_bucket = 0;

      vector_locks_borrow(sketch->keys, offseted, (void **)&saved_hash);
      vector_locks_borrow(sketch->buckets, offseted, (void **)&saved_bucket);

      (*saved_hash) = sketch->internal[lcore_id].hashes[i];
      (*saved_bucket) = 0;
      map_locks_put(sketch->clients, saved_hash, bucket_index);

      vector_locks_return(sketch->keys, offseted, saved_hash);
      vector_locks_return(sketch->buckets, offseted, saved_bucket);
    } else {
      dchain_locks_rejuvenate_index(sketch->allocators[i], bucket_index, now);
      uint32_t *bucket;
      int offseted = bucket_index + sketch->capacity * i;
      vector_locks_borrow(sketch->buckets, offseted, (void **)&bucket);
      (*bucket)++;
      vector_locks_return(sketch->buckets, offseted, bucket);
    }
  }

  return true;
}

void sketch_locks_expire(struct SketchLocks *sketch, vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  int offset = 0;
  int index = -1;

  for (int i = 0; i < SKETCH_HASHES; i++) {
    offset = i * sketch->capacity;

    while (dchain_locks_expire_one_index(sketch->allocators[i], &index, time)) {
      if (!*write_state_ptr) {
        *write_attempt_ptr = true;
        return;
      }

      void *key;
      vector_locks_borrow(sketch->keys, index + offset, &key);
      map_locks_erase(sketch->clients, key, &key);
      vector_locks_return(sketch->keys, index + offset, key);
    }
  }
}

#define MAX_CHT_HEIGHT 40000

uint64_t cht_loop(uint64_t k, uint64_t capacity) {
  uint64_t g = k % capacity;
  return g;
}

int cht_locks_fill_cht(struct VectorLocks *cht, uint32_t cht_height,
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
      vector_locks_borrow(cht,
                          (int)(backend_capacity * ((uint32_t)bucket_id) +
                                ((uint32_t)priority)),
                          (void **)&value);
      *value = j;
      vector_locks_return(cht,
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

int cht_locks_find_preferred_available_backend(
    uint64_t hash, struct VectorLocks *cht,
    struct DoubleChainLocks *active_backends, uint32_t cht_height,
    uint32_t backend_capacity, int *chosen_backend) {
  uint64_t start = cht_loop(hash, cht_height);
  for (uint32_t i = 0; i < backend_capacity; ++i) {
    uint64_t candidate_idx =
        start * backend_capacity +
        i; // There was a bug, right here, untill I tried to prove this.

    uint32_t *candidate;
    vector_locks_borrow(cht, (int)candidate_idx, (void **)&candidate);

    if (dchain_locks_is_index_allocated(active_backends, (int)*candidate)) {
      *chosen_backend = (int)*candidate;
      vector_locks_return(cht, (int)candidate_idx, candidate);
      return 1;
    }

    vector_locks_return(cht, (int)candidate_idx, candidate);
  }

  return 0;
}

int expire_items_single_map_offseted_locks(struct DoubleChainLocks *chain,
                                           struct VectorLocks *vector,
                                           struct MapLocks *map,
                                           vigor_time_t time, int offset) {
  assert(offset >= 0);

  int count = 0;
  int index = -1;

  while (dchain_locks_expire_one_index(chain, &index, time)) {
    void *key;
    vector_locks_borrow(vector, index + offset, &key);
    map_locks_erase(map, key, &key);
    vector_locks_return(vector, index + offset, key);
    ++count;
  }

  return count;
}

int expire_items_single_map_iteratively_locks(struct VectorLocks *vector,
                                              struct MapLocks *map, int start,
                                              int n_elems) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (n_elems != 0 && !*write_state_ptr) {
    *write_attempt_ptr = true;
    return 1;
  }

  assert(start >= 0);
  assert(n_elems >= 0);
  void *key;
  for (int i = start; i < n_elems; i++) {
    vector_locks_borrow(vector, i, (void **)&key);
    map_locks_erase(map, key, (void **)&key);
    vector_locks_return(vector, i, key);
  }
}

/**********************************************
 *
 *                  NF-LOCKS
 *
 **********************************************/

typedef struct {
  rte_atomic32_t atom;
} __attribute__((aligned(64))) atom_t;

typedef struct {
  atom_t *tokens;
  atom_t write_token;
} nf_lock_t;

static inline void nf_lock_init(nf_lock_t *nfl) {
  nfl->tokens = (atom_t *)rte_malloc(NULL, sizeof(atom_t) * RTE_MAX_LCORE, 64);

  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    rte_atomic32_init(&nfl->tokens[lcore_id].atom);
  }

  rte_atomic32_init(&nfl->write_token.atom);
}

static inline void nf_lock_allow_writes(nf_lock_t *nfl) {
  unsigned lcore_id = rte_lcore_id();
  rte_atomic32_clear(&nfl->tokens[lcore_id].atom);
}

static inline void nf_lock_block_writes(nf_lock_t *nfl) {
  unsigned lcore_id = rte_lcore_id();
  while (!rte_atomic32_test_and_set(&nfl->tokens[lcore_id].atom)) {
    // prevent the compiler from removing this loop
    __asm__ __volatile__("");
  }
}

static inline void nf_lock_write_lock(nf_lock_t *nfl) {
  unsigned lcore_id = rte_lcore_id();
  rte_atomic32_clear(&nfl->tokens[lcore_id].atom);

  while (!rte_atomic32_test_and_set(&nfl->write_token.atom)) {
    // prevent the compiler from removing this loop
    __asm__ __volatile__("");
  }

  RTE_LCORE_FOREACH(lcore_id) {
    while (!rte_atomic32_test_and_set(&nfl->tokens[lcore_id].atom)) {
      __asm__ __volatile__("");
    }
  }
}

static inline void nf_lock_write_unlock(nf_lock_t *nfl) {
  unsigned lcore_id;
  RTE_LCORE_FOREACH(lcore_id) {
    rte_atomic32_clear(&nfl->tokens[lcore_id].atom);
  }

  rte_atomic32_clear(&nfl->write_token.atom);
}

static nf_lock_t nf_lock;

static void nf_util_init_locks() { nf_lock_init(&nf_lock); }

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
 *                  NF-RSS
 *
 **********************************************/

#define MBUF_CACHE_SIZE 256
#define RSS_HASH_KEY_LENGTH 52
#define MAX_NUM_DEVICES 32 // this is quite arbitrary...

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

#define RETA_CONF_SIZE (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

typedef struct {
  uint16_t lut[ETH_RSS_RETA_SIZE_512];
  bool set;
} reta_t;

reta_t retas_per_device[MAX_NUM_DEVICES];

void set_reta(uint16_t device) {
  if (!retas_per_device[device].set) {
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
    reta_conf[reta_id].reta[reta_pos] = retas_per_device[device].lut[bucket];
  }

  /* RETA update */
  rte_eth_dev_rss_reta_update(device, reta_conf, dev_info.reta_size);

  printf("Set RETA for device %u\n", device);
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
  struct rte_eth_conf device_conf = { 0 };
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

  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  printf("Core %u forwarding packets.\n", rte_lcore_id());

  if (rte_eth_dev_count_avail() != 2) {
    rte_exit(EXIT_FAILURE, "We assume there will be exactly 2 devices.");
  }

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

        *write_attempt_ptr = false;
        *write_state_ptr = false;

        nf_lock_block_writes(&nf_lock);
        uint16_t dst_device =
            nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, VIGOR_NOW);

        if (*write_attempt_ptr) {
          *write_state_ptr = true;

          nf_lock_write_lock(&nf_lock);
          uint16_t dst_device =
              nf_process(mbufs[n]->port, data, mbufs[n]->pkt_len, VIGOR_NOW);
          nf_lock_write_unlock(&nf_lock);
        } else {
          nf_lock_allow_writes(&nf_lock);
        }

        if (dst_device == VIGOR_DEVICE) {
          rte_pktmbuf_free(mbufs[n]);
        } else if (dst_device == FLOOD_FRAME) {
          flood(mbufs[n], VIGOR_DEVICES_COUNT, queue_id);
        } else { // includes flood when 2 devices, which is equivalent to just
                 // a
                 // send
          mbufs_to_send[tx_count] = mbufs[n];
          tx_count++;
        }
      }

      uint16_t sent_count =
          rte_eth_tx_burst(1 - VIGOR_DEVICE, queue_id, mbufs_to_send, tx_count);
      for (uint16_t n = sent_count; n < tx_count; n++) {
        rte_pktmbuf_free(mbufs[n]); // should not happen, but we're in the
                                    // unverified case anyway
      }
    }
  }
}

struct args_t {
  char *pcap_fname;
  bool valid_pcap;
};

struct args_t app_parse_args(int argc, char **argv) {
  struct args_t args;

  args.valid_pcap = false;

  if (argc <= 1) {
    return args;
  }

  args.pcap_fname = argv[1];
  args.valid_pcap = true;
  return args;
}

struct pcap_pkt_hdr_t {
  struct ether_header eth_hdr;
  struct iphdr ip_hdr;
  struct udphdr udp_hdr;
} __attribute__((packed));

struct rss_bucket_t {
  uint16_t id;
  uint64_t counter;
};

struct rss_buckets_t {
  uint16_t num_buckets;
  struct rss_bucket_t buckets[ETH_RSS_RETA_SIZE_512];
};

struct rss_core_t {
  uint16_t id;
  uint64_t total_counter;
  struct rss_buckets_t buckets;
};

struct rss_cores_t {
  uint16_t num_cores;
  struct rss_core_t cores[RTE_MAX_LCORE];
};

struct rss_cores_groups_t {
  uint64_t counter_goal;

  uint16_t num_underloaded;
  uint16_t underloaded[RTE_MAX_LCORE];

  uint16_t num_overloaded;
  uint16_t overloaded[RTE_MAX_LCORE];
};

int cmp_cores_increasing(const void *a, const void *b, void *args) {
  struct rss_cores_t *cores = (struct rss_cores_t *)args;

  uint16_t *core1 = (uint16_t *)a;
  uint16_t *core2 = (uint16_t *)b;

  uint64_t counter1 = cores->cores[*core1].total_counter;
  uint64_t counter2 = cores->cores[*core2].total_counter;

  return counter1 - counter2;
}

int cmp_buckets_increasing(const void *a, const void *b) {
  struct rss_bucket_t *bucket1 = (struct rss_bucket_t *)a;
  struct rss_bucket_t *bucket2 = (struct rss_bucket_t *)b;

  return bucket1->counter - bucket2->counter;
}

int cmp_buckets_decreasing(const void *a, const void *b) {
  return -1 * cmp_buckets_increasing(a, b);
}

int cmp_cores_decreasing(const void *a, const void *b, void *args) {
  return -1 * cmp_cores_increasing(a, b, args);
}

void rss_lut_balancer_init_buckets(struct rss_buckets_t *buckets) {
  buckets->num_buckets = ETH_RSS_RETA_SIZE_512;
  for (int b = 0; b < buckets->num_buckets; b++) {
    buckets->buckets[b].id = b;
    buckets->buckets[b].counter = 0;
  }
}

void rss_lut_balancer_init_lut(unsigned device) {
  int num_cores = rte_lcore_count();

  // Set LUT default values.
  retas_per_device[device].set = true;
  for (int b = 0; b < ETH_RSS_RETA_SIZE_512; b++) {
    retas_per_device[device].lut[b] = b % num_cores;
  }
}

void rss_lut_balancer_init_cores(unsigned device, struct rss_buckets_t buckets,
                                 struct rss_cores_t *cores) {
  cores->num_cores = rte_lcore_count();
  for (int c = 0; c < cores->num_cores; c++) {
    cores->cores[c].id = c;
    cores->cores[c].total_counter = 0;
    cores->cores[c].buckets.num_buckets = 0;
  }

  // Group bucket counters by core.
  for (int b = 0; b < buckets.num_buckets; b++) {
    struct rss_bucket_t bucket = buckets.buckets[b];

    uint16_t chosen_core = retas_per_device[device].lut[bucket.id];
    uint16_t num_buckets = cores->cores[chosen_core].buckets.num_buckets;

    cores->cores[chosen_core].buckets.buckets[num_buckets] = bucket;
    cores->cores[chosen_core].buckets.num_buckets++;

    cores->cores[chosen_core].total_counter += bucket.counter;
  }
}

void rss_lut_balancer_get_core_groups(struct rss_cores_t cores,
                                      struct rss_cores_groups_t *core_groups) {
  uint64_t total_counter = 0;

  for (int c = 0; c < cores.num_cores; c++) {
    total_counter += cores.cores[c].total_counter;
  }

  core_groups->counter_goal =
      (uint64_t)((double)total_counter / (double)cores.num_cores);
  core_groups->num_overloaded = 0;
  core_groups->num_underloaded = 0;

  for (int c = 0; c < cores.num_cores; c++) {
    if (cores.cores[c].total_counter > core_groups->counter_goal) {
      core_groups->overloaded[core_groups->num_overloaded] = c;
      core_groups->num_overloaded++;
    } else {
      core_groups->underloaded[core_groups->num_underloaded] = c;
      core_groups->num_underloaded++;
    }
  }
}

void rss_lut_balancer_sort(struct rss_cores_t *cores,
                           struct rss_cores_groups_t *core_groups) {
  for (int c = 0; c < cores->num_cores; c++) {
    qsort(cores->cores[c].buckets.buckets, cores->cores[c].buckets.num_buckets,
          sizeof(struct rss_bucket_t), cmp_buckets_decreasing);
  }

  qsort_r(core_groups->underloaded, core_groups->num_underloaded,
          sizeof(uint16_t), cmp_cores_increasing, cores);
  qsort_r(core_groups->overloaded, core_groups->num_overloaded,
          sizeof(uint16_t), cmp_cores_decreasing, cores);
}

void rss_lut_balancer_migrate_bucket(struct rss_cores_t *cores,
                                     struct rss_cores_groups_t *core_groups,
                                     uint16_t bucket_idx, uint16_t src_core,
                                     uint16_t dst_core) {
  struct rss_bucket_t *bucket =
      &cores->cores[src_core].buckets.buckets[bucket_idx];

  uint16_t src_num_buckets = cores->cores[src_core].buckets.num_buckets;
  uint16_t dst_num_buckets = cores->cores[dst_core].buckets.num_buckets;

  assert(src_num_buckets >= 2);
  assert(dst_num_buckets >= 1);

  assert(src_num_buckets <= ETH_RSS_RETA_SIZE_512);
  assert(dst_num_buckets < ETH_RSS_RETA_SIZE_512);

  // Update the total counters.
  cores->cores[dst_core].total_counter += bucket->counter;
  cores->cores[src_core].total_counter -= bucket->counter;

  // Append to tail.
  cores->cores[dst_core].buckets.buckets[dst_num_buckets] = *bucket;
  cores->cores[dst_core].buckets.num_buckets++;

  // Pull the tail bucket to fill the place of the leaving one.
  *bucket = cores->cores[src_core].buckets.buckets[src_num_buckets - 1];
  cores->cores[src_core].buckets.num_buckets--;
}

bool rss_lut_balancer_balance_groups(struct rss_cores_t *cores,
                                     struct rss_cores_groups_t *core_groups,
                                     bool allow_big_atom_migration) {
  bool changes = false;

  for (int over_idx = 0; over_idx < core_groups->num_overloaded; over_idx++) {
    uint16_t overloaded_core = core_groups->overloaded[over_idx];
    int bucket_idx = 0;
    int under_idx = 0;

    // Keep going until the overload core becomes underloaded.
    while (cores->cores[overloaded_core].total_counter >
           core_groups->counter_goal) {
      // No more buckets to move.
      if (bucket_idx >= cores->cores[overloaded_core].buckets.num_buckets) {
        break;
      }

      // No more underloaded available cores.
      if (under_idx >= core_groups->num_underloaded) {
        break;
      }

      uint16_t underloaded_core = core_groups->underloaded[under_idx];
      uint64_t load =
          cores->cores[overloaded_core].buckets.buckets[bucket_idx].counter;

      // Is the load on this bucket alone bigger than the target?
      bool is_big_atom = load > core_groups->counter_goal;

      if (is_big_atom && allow_big_atom_migration) {
        // This will overload, but we only overload one underloaded core at a
        // time.
        rss_lut_balancer_migrate_bucket(cores, core_groups, bucket_idx,
                                        overloaded_core, underloaded_core);
        under_idx++;
        bucket_idx++;
        changes = true;
        continue;
      }

      // Underloaded core would become an overloaded core.
      // Let's see if the next one is available to receive this load.
      bool will_overload = cores->cores[underloaded_core].total_counter + load >
                           core_groups->counter_goal;

      if (will_overload) {
        under_idx++;
        continue;
      }

      rss_lut_balancer_migrate_bucket(cores, core_groups, bucket_idx,
                                      overloaded_core, underloaded_core);
      changes = true;

      if (will_overload) {
        under_idx++;
      }
    }
  }

  return changes;
}

void rss_lut_balancer_balance_elephants(struct rss_cores_t *cores) {
  struct rss_cores_groups_t core_groups;
  rss_lut_balancer_get_core_groups(*cores, &core_groups);

  qsort_r(core_groups.underloaded, core_groups.num_underloaded,
          sizeof(uint16_t), cmp_cores_increasing, cores);
  qsort_r(core_groups.overloaded, core_groups.num_overloaded, sizeof(uint16_t),
          cmp_cores_decreasing, cores);

  for (int c = 0; c < cores->num_cores; c++) {
    qsort(cores->cores[c].buckets.buckets, cores->cores[c].buckets.num_buckets,
          sizeof(struct rss_bucket_t), cmp_buckets_decreasing);
  }

  rss_lut_balancer_balance_groups(cores, &core_groups, true);
}

void rss_lut_balancer_balance_mice(struct rss_cores_t *cores) {
  struct rss_cores_groups_t core_groups;

  while (true) {
    rss_lut_balancer_get_core_groups(*cores, &core_groups);

    qsort_r(core_groups.underloaded, core_groups.num_underloaded,
            sizeof(uint16_t), cmp_cores_increasing, cores);
    qsort_r(core_groups.overloaded, core_groups.num_overloaded,
            sizeof(uint16_t), cmp_cores_decreasing, cores);

    for (int c = 0; c < cores->num_cores; c++) {
      qsort(cores->cores[c].buckets.buckets,
            cores->cores[c].buckets.num_buckets, sizeof(struct rss_bucket_t),
            cmp_buckets_increasing);
    }

    if (!rss_lut_balancer_balance_groups(cores, &core_groups, false)) {
      break;
    }
  }
}

void rss_lut_balancer_print_cores(struct rss_cores_t cores) {
  struct rss_cores_groups_t core_groups;
  rss_lut_balancer_get_core_groups(cores, &core_groups);
  rss_lut_balancer_sort(&cores, &core_groups);

  const int NUM_BUCKETS_SHOWN = 3;

  printf("======================= LUT BALANCING =======================\n");
  printf("Goal: %lu\n", core_groups.counter_goal);

  printf("Overloaded:\n");
  for (int c = 0; c < core_groups.num_overloaded; c++) {
    struct rss_core_t core = cores.cores[core_groups.overloaded[c]];
    printf("  Core %2d: %9lu", core.id, core.total_counter);

    printf(", #buckets: %3u", core.buckets.num_buckets);
    printf(", buckets: [");
    for (int i = 0; i < core.buckets.num_buckets; i++) {
      if (i < NUM_BUCKETS_SHOWN) {
        printf("{bucket:%3u, pkts:%8lu},", core.buckets.buckets[i].id,
               core.buckets.buckets[i].counter);
      } else {
        printf("...");
        break;
      }
    }
    printf("]\n");
  }

  printf("Underloaded:\n");
  for (int c = 0; c < core_groups.num_underloaded; c++) {
    struct rss_core_t core = cores.cores[core_groups.underloaded[c]];
    printf("  Core %2d: %9lu", core.id, core.total_counter);

    printf(", #buckets: %3u", core.buckets.num_buckets);
    printf(", buckets: [");
    for (int i = 0; i < core.buckets.num_buckets; i++) {
      if (i < NUM_BUCKETS_SHOWN) {
        printf("{bucket:%3u, pkts:%8lu},", core.buckets.buckets[i].id,
               core.buckets.buckets[i].counter);
      } else {
        printf("...");
        break;
      }
    }
    printf("]\n");
  }
  printf("================================================================\n");
}

struct rss_buckets_t rss_lut_buckets_from_pcap(unsigned device,
                                               const char *pcap_fname) {
  char errbuff[PCAP_ERRBUF_SIZE];
  uint64_t pkt_counter = 0;

  pcap_t *pcap = pcap_open_offline(pcap_fname, errbuff);

  if (pcap == NULL) {
    rte_exit(EXIT_FAILURE, "Error opening pcap: %s", errbuff);
  }

  struct pcap_pkthdr *header;
  const u_char *data;

  uint8_t key[RSS_HASH_KEY_LENGTH];
  rte_convert_rss_key((uint32_t *)rss_conf[device].rss_key, (uint32_t *)key,
                      rss_conf[device].rss_key_len);

  struct rss_buckets_t buckets;
  rss_lut_balancer_init_buckets(&buckets);

  while (pcap_next_ex(pcap, &header, &data) >= 0) {
    pkt_counter++;

    const struct pcap_pkt_hdr_t *pkt = (const struct pcap_pkt_hdr_t *)data;

    union rte_thash_tuple tuple;
    tuple.v4.src_addr = rte_be_to_cpu_32(pkt->ip_hdr.saddr);
    tuple.v4.dst_addr = rte_be_to_cpu_32(pkt->ip_hdr.daddr);
    tuple.v4.sport = rte_be_to_cpu_16(pkt->udp_hdr.uh_sport);
    tuple.v4.dport = rte_be_to_cpu_16(pkt->udp_hdr.uh_dport);

    uint32_t hash =
        rte_softrss_be((uint32_t *)&tuple, RTE_THASH_V4_L4_LEN, key);

    // As per X710/e810
    int chosen_bucket = hash & 0x1ff;
    assert(chosen_bucket < ETH_RSS_RETA_SIZE_512);
    assert(buckets.buckets[chosen_bucket].id == chosen_bucket);
    buckets.buckets[chosen_bucket].counter++;
  }

  return buckets;
}

void rss_lut_balance(unsigned device, const char *pcap_fname) {
  struct rss_buckets_t buckets = rss_lut_buckets_from_pcap(device, pcap_fname);

  struct rss_cores_t cores;
  rss_lut_balancer_init_cores(device, buckets, &cores);

  printf("Before:\n");
  rss_lut_balancer_print_cores(cores);

  rss_lut_balancer_balance_elephants(&cores);
  rss_lut_balancer_balance_mice(&cores);

  rss_lut_balancer_balance_elephants(&cores);
  rss_lut_balancer_balance_mice(&cores);

  printf("After:\n");
  rss_lut_balancer_print_cores(cores);

  // Finally, configure the LUTs
  for (int c = 0; c < cores.num_cores; c++) {
    struct rss_core_t core = cores.cores[c];

    for (int b = 0; b < cores.cores[c].buckets.num_buckets; b++) {
      struct rss_bucket_t bucket = core.buckets.buckets[b];
      retas_per_device[device].lut[bucket.id] = core.id;
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

  struct args_t args = app_parse_args(argc, argv);

  // Create a memory pool
  unsigned nb_devices = rte_eth_dev_count_avail();

  nf_util_init_locks();

  char MBUF_POOL_NAME[20];
  struct rte_mempool **mbuf_pools;
  mbuf_pools = (struct rte_mempool **)rte_malloc(
      NULL, sizeof(struct rte_mempool *) * rte_lcore_count(), 64);

  unsigned lcore_id;
  unsigned lcore_idx = 0;
  RTE_LCORE_FOREACH(lcore_id) {
    sprintf(MBUF_POOL_NAME, "MEMORY_POOL_%u", lcore_idx);

    mbuf_pools[lcore_idx] =
        rte_pktmbuf_pool_create(MBUF_POOL_NAME,                    // name
                                MEMPOOL_BUFFER_COUNT * nb_devices, // #elements
                                MBUF_CACHE_SIZE, // cache size (per-lcore)
                                0, // application private area size
                                RTE_MBUF_DEFAULT_BUF_SIZE, // data buffer size
                                rte_socket_id()            // socket ID
        );

    if (mbuf_pools[lcore_idx] == NULL) {
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool: %s\n",
               rte_strerror(rte_errno));
    }

    lcore_idx++;
  }

  // Initialize all devices
  for (uint16_t device = 0; device < nb_devices; device++) {
    rss_lut_balancer_init_lut(device);

    if (args.valid_pcap) {
      rss_lut_balance(device, args.pcap_fname);
    }

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

struct DynamicValue {
  uint64_t bucket_size;
  int64_t bucket_time;
};
struct ip_addr {
  uint32_t addr;
};
uint32_t ip_addr_hash(void* obj) {
  struct ip_addr *id = (struct ip_addr *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->addr);
  return hash;
}
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

uint8_t hash_key_0[RSS_HASH_KEY_LENGTH] = {
  0xe0, 0xb9, 0x90, 0xae, 0x7f, 0x2, 0x1d, 0x56, 
  0xdb, 0x72, 0xd0, 0x37, 0x14, 0x86, 0xe9, 0x89, 
  0xd2, 0xb4, 0x1f, 0x71, 0x34, 0x7, 0xc, 0xce, 
  0x46, 0x5a, 0xae, 0x5b, 0xe9, 0x38, 0x67, 0xc9, 
  0xf2, 0xf7, 0x78, 0x71, 0xf9, 0x95, 0xc7, 0xd5, 
  0x7, 0x98, 0xc, 0x1b, 0x1e, 0xf5, 0xa5, 0xf1, 
  0xa9, 0xc4, 0x62, 0xde
};
uint8_t hash_key_1[RSS_HASH_KEY_LENGTH] = {
  0xbf, 0xa8, 0xe2, 0xe8, 0x24, 0x13, 0x4a, 0xbe, 
  0x58, 0x53, 0x3b, 0x4a, 0xe7, 0xd9, 0x1, 0x6e, 
  0x57, 0x36, 0x7a, 0x3a, 0x78, 0x71, 0xd3, 0x32, 
  0xf4, 0x0, 0x27, 0xa9, 0x90, 0x44, 0xc5, 0x50, 
  0xec, 0xa7, 0x38, 0x11, 0xba, 0x83, 0xcf, 0x13, 
  0xd6, 0xa, 0x5d, 0xbd, 0xe3, 0x5e, 0x2c, 0x3b, 
  0x94, 0xa6, 0x75, 0xd
};

struct rte_eth_rss_conf rss_conf[MAX_NUM_DEVICES] = {
  {
    .rss_key = hash_key_0,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP
  },
  {
    .rss_key = hash_key_1,
    .rss_key_len = RSS_HASH_KEY_LENGTH,
    .rss_hf = ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP
  }
};

bool ip_addr_eq(void* a, void* b) ;
uint32_t ip_addr_hash(void* obj) ;
void DynamicValue_allocate(void* obj) ;
void ip_addr_allocate(void* obj) ;
struct MapLocks* map;
struct DoubleChainLocks* dchain;
struct VectorLocks* vector;
struct VectorLocks* vector_1;
struct MapLocks* map_1;
struct DoubleChainLocks* dchain_1;
struct VectorLocks* vector_2;
struct VectorLocks* vector_3;
struct MapLocks* map_2;
struct DoubleChainLocks* dchain_2;
struct VectorLocks* vector_4;
struct VectorLocks* vector_5;

bool nf_init() {

  if (!(rte_get_master_lcore() == rte_lcore_id())) {
    return 1;
  }

  int map_allocation_succeeded__1 = map_locks_allocate(ip_addr_eq, ip_addr_hash, 65536u, &map);

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
    int is_dchain_allocated__4 = dchain_locks_allocate(65536u, &dchain);

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
      int vector_alloc_success__7 = vector_locks_allocate(16u, 65536u, DynamicValue_allocate, &vector);

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
        int vector_alloc_success__10 = vector_locks_allocate(4u, 65536u, ip_addr_allocate, &vector_1);

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
          int map_allocation_succeeded__13 = map_locks_allocate(ip_addr_eq, ip_addr_hash, 65536u, &map_1);

          // 1891
          // 1892
          // 1893
          // 1894
          // 1895
          // 1896
          // 1897
          // 1898
          if (map_allocation_succeeded__13) {
            int is_dchain_allocated__16 = dchain_locks_allocate(65536u, &dchain_1);

            // 1891
            // 1892
            // 1893
            // 1894
            // 1895
            // 1896
            // 1897
            if (is_dchain_allocated__16) {
              int vector_alloc_success__19 = vector_locks_allocate(16u, 65536u, DynamicValue_allocate, &vector_2);

              // 1891
              // 1892
              // 1893
              // 1894
              // 1895
              // 1896
              if (vector_alloc_success__19) {
                int vector_alloc_success__22 = vector_locks_allocate(4u, 65536u, ip_addr_allocate, &vector_3);

                // 1891
                // 1892
                // 1893
                // 1894
                // 1895
                if (vector_alloc_success__22) {
                  int map_allocation_succeeded__25 = map_locks_allocate(ip_addr_eq, ip_addr_hash, 65536u, &map_2);

                  // 1891
                  // 1892
                  // 1893
                  // 1894
                  if (map_allocation_succeeded__25) {
                    int is_dchain_allocated__28 = dchain_locks_allocate(65536u, &dchain_2);

                    // 1891
                    // 1892
                    // 1893
                    if (is_dchain_allocated__28) {
                      int vector_alloc_success__31 = vector_locks_allocate(16u, 65536u, DynamicValue_allocate, &vector_4);

                      // 1891
                      // 1892
                      if (vector_alloc_success__31) {
                        int vector_alloc_success__34 = vector_locks_allocate(4u, 65536u, ip_addr_allocate, &vector_5);

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
  bool* write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool* write_state_ptr = &RTE_PER_LCORE(write_state);
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
    int number_of_freed_flows__56 = expire_items_single_map_locks(dchain, vector_1, map, now - 6000000000000000ul);

    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
      return 1;
    }

    int number_of_freed_flows__57 = expire_items_single_map_locks(dchain_1, vector_3, map_1, now - 6000000000000000ul);

    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
      return 1;
    }

    int number_of_freed_flows__58 = expire_items_single_map_locks(dchain_2, vector_5, map_2, now - 6000000000000000ul);

    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
      return 1;
    }


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
      int map_has_this_key__68 = map_locks_get(map, map_key, &map_value_out);

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
        int out_of_space__71 = !dchain_locks_allocate_new_index(dchain, &new_index__71, now);

        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
          return 1;
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
        if (false == ((out_of_space__71) & (0u == number_of_freed_flows__56))) {

          if (!write_state_ptr[0]) {
            write_attempt_ptr[0] = 1;
            return 1;
          }

          uint8_t* vector_value_out = 0u;
          vector_locks_borrow(vector_1, new_index__71, (void**)(&vector_value_out));
          vector_value_out[0u] = ipv4_header_1->src_addr & 0xff;
          vector_value_out[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
          vector_value_out[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
          vector_value_out[3u] = ((ipv4_header_1->src_addr & 4043309055u) >> 24ul) & 0xff;

          if (!write_state_ptr[0]) {
            write_attempt_ptr[0] = 1;
            return 1;
          }

          uint8_t* vector_value_out_1 = 0u;
          vector_locks_borrow(vector, new_index__71, (void**)(&vector_value_out_1));
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
          map_locks_put(map, vector_value_out, new_index__71);

          if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
            return 1;
          }

          vector_locks_return(vector_1, new_index__71, vector_value_out);
          vector_locks_return(vector, new_index__71, vector_value_out_1);
          uint8_t map_key_1[4];
          map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
          map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
          map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
          map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
          int map_value_out_1;
          int map_has_this_key__79 = map_locks_get(map_1, map_key_1, &map_value_out_1);

          // 1906
          // 1907
          // 1908
          // 1909
          // 1910
          // 1911
          // 1912
          if (0u == map_has_this_key__79) {
            uint32_t new_index__82;
            int out_of_space__82 = !dchain_locks_allocate_new_index(dchain_1, &new_index__82, now);

            if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
              return 1;
            }


            // 1906
            // 1907
            // 1908
            // 1909
            // 1910
            // 1911
            if (false == ((out_of_space__82) & (0u == number_of_freed_flows__57))) {

              if (!write_state_ptr[0]) {
                write_attempt_ptr[0] = 1;
                return 1;
              }

              uint8_t* vector_value_out_2 = 0u;
              vector_locks_borrow(vector_3, new_index__82, (void**)(&vector_value_out_2));
              vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
              vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              vector_value_out_2[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;

              if (!write_state_ptr[0]) {
                write_attempt_ptr[0] = 1;
                return 1;
              }

              uint8_t* vector_value_out_3 = 0u;
              vector_locks_borrow(vector_2, new_index__82, (void**)(&vector_value_out_3));
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
              map_locks_put(map_1, vector_value_out_2, new_index__82);

              if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                return 1;
              }

              vector_locks_return(vector_3, new_index__82, vector_value_out_2);
              vector_locks_return(vector_2, new_index__82, vector_value_out_3);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__90 = map_locks_get(map_2, map_key_2, &map_value_out_2);

              // 1906
              // 1907
              if (0u == map_has_this_key__90) {
                uint32_t new_index__93;
                int out_of_space__93 = !dchain_locks_allocate_new_index(dchain_2, &new_index__93, now);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }


                // 1906
                if (false == ((out_of_space__93) & (0u == number_of_freed_flows__58))) {

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_4 = 0u;
                  vector_locks_borrow(vector_5, new_index__93, (void**)(&vector_value_out_4));
                  vector_value_out_4[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_4[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_4[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_4[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_5 = 0u;
                  vector_locks_borrow(vector_4, new_index__93, (void**)(&vector_value_out_5));
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
                  map_locks_put(map_2, vector_value_out_4, new_index__93);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }

                  vector_locks_return(vector_5, new_index__93, vector_value_out_4);
                  vector_locks_return(vector_4, new_index__93, vector_value_out_5);
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
                dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_4 = 0u;
                vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_4));
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
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_4);
                      return 1;
                    }

                    // 1909
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_4);
                      return 1;
                    } // !((vector_value_out_4[0ul] + ((625ul * (now - vector_value_out_4[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 1910
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_4);
                    return 1;
                  } // !((vector_value_out_4[0ul] + ((625ul * (now - vector_value_out_4[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 1911
                else {
                  vector_locks_return(vector_4, map_value_out_2, vector_value_out_4);
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
            dchain_locks_rejuvenate_index(dchain_1, map_value_out_1, now);

            if (!write_state_ptr[0]) {
              write_attempt_ptr[0] = 1;
              return 1;
            }

            uint8_t* vector_value_out_2 = 0u;
            vector_locks_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_2));
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__171 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 1913
                  // 1914
                  if (0u == map_has_this_key__171) {
                    uint32_t new_index__174;
                    int out_of_space__174 = !dchain_locks_allocate_new_index(dchain_2, &new_index__174, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 1913
                    if (false == ((out_of_space__174) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_5, new_index__174, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_4 = 0u;
                      vector_locks_borrow(vector_4, new_index__174, (void**)(&vector_value_out_4));
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
                      map_locks_put(map_2, vector_value_out_3, new_index__174);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__174, vector_value_out_3);
                      vector_locks_return(vector_4, new_index__174, vector_value_out_4);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1916
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1917
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1918
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__237 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 1919
                  // 1920
                  if (0u == map_has_this_key__237) {
                    uint32_t new_index__240;
                    int out_of_space__240 = !dchain_locks_allocate_new_index(dchain_2, &new_index__240, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 1919
                    if (false == ((out_of_space__240) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_5, new_index__240, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_4 = 0u;
                      vector_locks_borrow(vector_4, new_index__240, (void**)(&vector_value_out_4));
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
                      map_locks_put(map_2, vector_value_out_3, new_index__240);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__240, vector_value_out_3);
                      vector_locks_return(vector_4, new_index__240, vector_value_out_4);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1922
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1923
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1924
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
                vector_locks_return(vector_2, map_value_out_1, vector_value_out_2);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__303 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                // 1925
                // 1926
                if (0u == map_has_this_key__303) {
                  uint32_t new_index__306;
                  int out_of_space__306 = !dchain_locks_allocate_new_index(dchain_2, &new_index__306, now);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }


                  // 1925
                  if (false == ((out_of_space__306) & (0u == number_of_freed_flows__58))) {

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_5, new_index__306, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_4 = 0u;
                    vector_locks_borrow(vector_4, new_index__306, (void**)(&vector_value_out_4));
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
                    map_locks_put(map_2, vector_value_out_3, new_index__306);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }

                    vector_locks_return(vector_5, new_index__306, vector_value_out_3);
                    vector_locks_return(vector_4, new_index__306, vector_value_out_4);
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
                  dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_3 = 0u;
                  vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      }

                      // 1928
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 1929
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 1930
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
              vector_locks_return(vector_2, map_value_out_1, vector_value_out_2);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__369 = map_locks_get(map_2, map_key_2, &map_value_out_2);

              // 1931
              // 1932
              if (0u == map_has_this_key__369) {
                uint32_t new_index__372;
                int out_of_space__372 = !dchain_locks_allocate_new_index(dchain_2, &new_index__372, now);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }


                // 1931
                if (false == ((out_of_space__372) & (0u == number_of_freed_flows__58))) {

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_3 = 0u;
                  vector_locks_borrow(vector_5, new_index__372, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_4 = 0u;
                  vector_locks_borrow(vector_4, new_index__372, (void**)(&vector_value_out_4));
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
                  map_locks_put(map_2, vector_value_out_3, new_index__372);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }

                  vector_locks_return(vector_5, new_index__372, vector_value_out_3);
                  vector_locks_return(vector_4, new_index__372, vector_value_out_4);
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
                dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_3 = 0u;
                vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    }

                    // 1934
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 1935
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                    return 1;
                  } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 1936
                else {
                  vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
        dchain_locks_rejuvenate_index(dchain, map_value_out, now);

        if (!write_state_ptr[0]) {
          write_attempt_ptr[0] = 1;
          return 1;
        }

        uint8_t* vector_value_out = 0u;
        vector_locks_borrow(vector, map_value_out, (void**)(&vector_value_out));
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
              vector_locks_return(vector, map_value_out, vector_value_out);
              uint8_t map_key_1[4];
              map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
              int map_value_out_1;
              int map_has_this_key__450 = map_locks_get(map_1, map_key_1, &map_value_out_1);

              // 1938
              // 1939
              // 1940
              // 1941
              // 1942
              // 1943
              // 1944
              if (0u == map_has_this_key__450) {
                uint32_t new_index__453;
                int out_of_space__453 = !dchain_locks_allocate_new_index(dchain_1, &new_index__453, now);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }


                // 1938
                // 1939
                // 1940
                // 1941
                // 1942
                // 1943
                if (false == ((out_of_space__453) & (0u == number_of_freed_flows__57))) {

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_1 = 0u;
                  vector_locks_borrow(vector_3, new_index__453, (void**)(&vector_value_out_1));
                  vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_2 = 0u;
                  vector_locks_borrow(vector_2, new_index__453, (void**)(&vector_value_out_2));
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
                  map_locks_put(map_1, vector_value_out_1, new_index__453);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }

                  vector_locks_return(vector_3, new_index__453, vector_value_out_1);
                  vector_locks_return(vector_2, new_index__453, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__461 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 1938
                  // 1939
                  if (0u == map_has_this_key__461) {
                    uint32_t new_index__464;
                    int out_of_space__464 = !dchain_locks_allocate_new_index(dchain_2, &new_index__464, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 1938
                    if (false == ((out_of_space__464) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_5, new_index__464, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_4 = 0u;
                      vector_locks_borrow(vector_4, new_index__464, (void**)(&vector_value_out_4));
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
                      map_locks_put(map_2, vector_value_out_3, new_index__464);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__464, vector_value_out_3);
                      vector_locks_return(vector_4, new_index__464, vector_value_out_4);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1941
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1942
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1943
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
                dchain_locks_rejuvenate_index(dchain_1, map_value_out_1, now);

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_1 = 0u;
                vector_locks_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
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
                      vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__542 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                      // 1945
                      // 1946
                      if (0u == map_has_this_key__542) {
                        uint32_t new_index__545;
                        int out_of_space__545 = !dchain_locks_allocate_new_index(dchain_2, &new_index__545, now);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }


                        // 1945
                        if (false == ((out_of_space__545) & (0u == number_of_freed_flows__58))) {

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_2 = 0u;
                          vector_locks_borrow(vector_5, new_index__545, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_3 = 0u;
                          vector_locks_borrow(vector_4, new_index__545, (void**)(&vector_value_out_3));
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
                          map_locks_put(map_2, vector_value_out_2, new_index__545);

                          if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                            return 1;
                          }

                          vector_locks_return(vector_5, new_index__545, vector_value_out_2);
                          vector_locks_return(vector_4, new_index__545, vector_value_out_3);
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
                        dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1948
                            else {
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1949
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1950
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                      vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__608 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                      // 1951
                      // 1952
                      if (0u == map_has_this_key__608) {
                        uint32_t new_index__611;
                        int out_of_space__611 = !dchain_locks_allocate_new_index(dchain_2, &new_index__611, now);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }


                        // 1951
                        if (false == ((out_of_space__611) & (0u == number_of_freed_flows__58))) {

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_2 = 0u;
                          vector_locks_borrow(vector_5, new_index__611, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_3 = 0u;
                          vector_locks_borrow(vector_4, new_index__611, (void**)(&vector_value_out_3));
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
                          map_locks_put(map_2, vector_value_out_2, new_index__611);

                          if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                            return 1;
                          }

                          vector_locks_return(vector_5, new_index__611, vector_value_out_2);
                          vector_locks_return(vector_4, new_index__611, vector_value_out_3);
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
                        dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1954
                            else {
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1955
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1956
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                    vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__674 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                    // 1957
                    // 1958
                    if (0u == map_has_this_key__674) {
                      uint32_t new_index__677;
                      int out_of_space__677 = !dchain_locks_allocate_new_index(dchain_2, &new_index__677, now);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }


                      // 1957
                      if (false == ((out_of_space__677) & (0u == number_of_freed_flows__58))) {

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_5, new_index__677, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_3 = 0u;
                        vector_locks_borrow(vector_4, new_index__677, (void**)(&vector_value_out_3));
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
                        map_locks_put(map_2, vector_value_out_2, new_index__677);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }

                        vector_locks_return(vector_5, new_index__677, vector_value_out_2);
                        vector_locks_return(vector_4, new_index__677, vector_value_out_3);
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
                      dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 1960
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 1961
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 1962
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__740 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 1963
                  // 1964
                  if (0u == map_has_this_key__740) {
                    uint32_t new_index__743;
                    int out_of_space__743 = !dchain_locks_allocate_new_index(dchain_2, &new_index__743, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 1963
                    if (false == ((out_of_space__743) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_5, new_index__743, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_4, new_index__743, (void**)(&vector_value_out_3));
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
                      map_locks_put(map_2, vector_value_out_2, new_index__743);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__743, vector_value_out_2);
                      vector_locks_return(vector_4, new_index__743, vector_value_out_3);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 1966
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1967
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1968
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
              vector_locks_return(vector, map_value_out, vector_value_out);
              uint8_t map_key_1[4];
              map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
              int map_value_out_1;
              int map_has_this_key__806 = map_locks_get(map_1, map_key_1, &map_value_out_1);

              // 1969
              // 1970
              // 1971
              // 1972
              // 1973
              // 1974
              // 1975
              if (0u == map_has_this_key__806) {
                uint32_t new_index__809;
                int out_of_space__809 = !dchain_locks_allocate_new_index(dchain_1, &new_index__809, now);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }


                // 1969
                // 1970
                // 1971
                // 1972
                // 1973
                // 1974
                if (false == ((out_of_space__809) & (0u == number_of_freed_flows__57))) {

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_1 = 0u;
                  vector_locks_borrow(vector_3, new_index__809, (void**)(&vector_value_out_1));
                  vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_2 = 0u;
                  vector_locks_borrow(vector_2, new_index__809, (void**)(&vector_value_out_2));
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
                  map_locks_put(map_1, vector_value_out_1, new_index__809);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }

                  vector_locks_return(vector_3, new_index__809, vector_value_out_1);
                  vector_locks_return(vector_2, new_index__809, vector_value_out_2);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__817 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 1969
                  // 1970
                  if (0u == map_has_this_key__817) {
                    uint32_t new_index__820;
                    int out_of_space__820 = !dchain_locks_allocate_new_index(dchain_2, &new_index__820, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 1969
                    if (false == ((out_of_space__820) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_5, new_index__820, (void**)(&vector_value_out_3));
                      vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_4 = 0u;
                      vector_locks_borrow(vector_4, new_index__820, (void**)(&vector_value_out_4));
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
                      map_locks_put(map_2, vector_value_out_3, new_index__820);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__820, vector_value_out_3);
                      vector_locks_return(vector_4, new_index__820, vector_value_out_4);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        }

                        // 1972
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                          return 1;
                        } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1973
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1974
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
                dchain_locks_rejuvenate_index(dchain_1, map_value_out_1, now);

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_1 = 0u;
                vector_locks_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
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
                      vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__898 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                      // 1976
                      // 1977
                      if (0u == map_has_this_key__898) {
                        uint32_t new_index__901;
                        int out_of_space__901 = !dchain_locks_allocate_new_index(dchain_2, &new_index__901, now);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }


                        // 1976
                        if (false == ((out_of_space__901) & (0u == number_of_freed_flows__58))) {

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_2 = 0u;
                          vector_locks_borrow(vector_5, new_index__901, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_3 = 0u;
                          vector_locks_borrow(vector_4, new_index__901, (void**)(&vector_value_out_3));
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
                          map_locks_put(map_2, vector_value_out_2, new_index__901);

                          if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                            return 1;
                          }

                          vector_locks_return(vector_5, new_index__901, vector_value_out_2);
                          vector_locks_return(vector_4, new_index__901, vector_value_out_3);
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
                        dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1979
                            else {
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1980
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1981
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                      vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                      uint8_t map_key_2[4];
                      map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                      map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                      int map_value_out_2;
                      int map_has_this_key__964 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                      // 1982
                      // 1983
                      if (0u == map_has_this_key__964) {
                        uint32_t new_index__967;
                        int out_of_space__967 = !dchain_locks_allocate_new_index(dchain_2, &new_index__967, now);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }


                        // 1982
                        if (false == ((out_of_space__967) & (0u == number_of_freed_flows__58))) {

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_2 = 0u;
                          vector_locks_borrow(vector_5, new_index__967, (void**)(&vector_value_out_2));
                          vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                          vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                          vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                          vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                          if (!write_state_ptr[0]) {
                            write_attempt_ptr[0] = 1;
                            return 1;
                          }

                          uint8_t* vector_value_out_3 = 0u;
                          vector_locks_borrow(vector_4, new_index__967, (void**)(&vector_value_out_3));
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
                          map_locks_put(map_2, vector_value_out_2, new_index__967);

                          if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                            return 1;
                          }

                          vector_locks_return(vector_5, new_index__967, vector_value_out_2);
                          vector_locks_return(vector_4, new_index__967, vector_value_out_3);
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
                        dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            }

                            // 1985
                            else {
                              vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                              return 1;
                            } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                          }

                          // 1986
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                        }

                        // 1987
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                    vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__1030 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                    // 1988
                    // 1989
                    if (0u == map_has_this_key__1030) {
                      uint32_t new_index__1033;
                      int out_of_space__1033 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1033, now);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }


                      // 1988
                      if (false == ((out_of_space__1033) & (0u == number_of_freed_flows__58))) {

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_5, new_index__1033, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_3 = 0u;
                        vector_locks_borrow(vector_4, new_index__1033, (void**)(&vector_value_out_3));
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
                        map_locks_put(map_2, vector_value_out_2, new_index__1033);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }

                        vector_locks_return(vector_5, new_index__1033, vector_value_out_2);
                        vector_locks_return(vector_4, new_index__1033, vector_value_out_3);
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
                      dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 1991
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 1992
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 1993
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1096 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 1994
                  // 1995
                  if (0u == map_has_this_key__1096) {
                    uint32_t new_index__1099;
                    int out_of_space__1099 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1099, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 1994
                    if (false == ((out_of_space__1099) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_5, new_index__1099, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_4, new_index__1099, (void**)(&vector_value_out_3));
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
                      map_locks_put(map_2, vector_value_out_2, new_index__1099);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__1099, vector_value_out_2);
                      vector_locks_return(vector_4, new_index__1099, vector_value_out_3);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 1997
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 1998
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 1999
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
            vector_locks_return(vector, map_value_out, vector_value_out);
            uint8_t map_key_1[4];
            map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
            map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
            map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
            map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
            int map_value_out_1;
            int map_has_this_key__1162 = map_locks_get(map_1, map_key_1, &map_value_out_1);

            // 2000
            // 2001
            // 2002
            // 2003
            // 2004
            // 2005
            // 2006
            if (0u == map_has_this_key__1162) {
              uint32_t new_index__1165;
              int out_of_space__1165 = !dchain_locks_allocate_new_index(dchain_1, &new_index__1165, now);

              if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                return 1;
              }


              // 2000
              // 2001
              // 2002
              // 2003
              // 2004
              // 2005
              if (false == ((out_of_space__1165) & (0u == number_of_freed_flows__57))) {

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_1 = 0u;
                vector_locks_borrow(vector_3, new_index__1165, (void**)(&vector_value_out_1));
                vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
                vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_2 = 0u;
                vector_locks_borrow(vector_2, new_index__1165, (void**)(&vector_value_out_2));
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
                map_locks_put(map_1, vector_value_out_1, new_index__1165);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }

                vector_locks_return(vector_3, new_index__1165, vector_value_out_1);
                vector_locks_return(vector_2, new_index__1165, vector_value_out_2);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__1173 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                // 2000
                // 2001
                if (0u == map_has_this_key__1173) {
                  uint32_t new_index__1176;
                  int out_of_space__1176 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1176, now);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }


                  // 2000
                  if (false == ((out_of_space__1176) & (0u == number_of_freed_flows__58))) {

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_5, new_index__1176, (void**)(&vector_value_out_3));
                    vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_4 = 0u;
                    vector_locks_borrow(vector_4, new_index__1176, (void**)(&vector_value_out_4));
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
                    map_locks_put(map_2, vector_value_out_3, new_index__1176);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }

                    vector_locks_return(vector_5, new_index__1176, vector_value_out_3);
                    vector_locks_return(vector_4, new_index__1176, vector_value_out_4);
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
                  dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_3 = 0u;
                  vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      }

                      // 2003
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                        return 1;
                      } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 2004
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 2005
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
              dchain_locks_rejuvenate_index(dchain_1, map_value_out_1, now);

              if (!write_state_ptr[0]) {
                write_attempt_ptr[0] = 1;
                return 1;
              }

              uint8_t* vector_value_out_1 = 0u;
              vector_locks_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
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
                    vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__1254 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                    // 2007
                    // 2008
                    if (0u == map_has_this_key__1254) {
                      uint32_t new_index__1257;
                      int out_of_space__1257 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1257, now);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }


                      // 2007
                      if (false == ((out_of_space__1257) & (0u == number_of_freed_flows__58))) {

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_5, new_index__1257, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_3 = 0u;
                        vector_locks_borrow(vector_4, new_index__1257, (void**)(&vector_value_out_3));
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
                        map_locks_put(map_2, vector_value_out_2, new_index__1257);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }

                        vector_locks_return(vector_5, new_index__1257, vector_value_out_2);
                        vector_locks_return(vector_4, new_index__1257, vector_value_out_3);
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
                      dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 2010
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 2011
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 2012
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                    vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                    uint8_t map_key_2[4];
                    map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                    map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                    int map_value_out_2;
                    int map_has_this_key__1320 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                    // 2013
                    // 2014
                    if (0u == map_has_this_key__1320) {
                      uint32_t new_index__1323;
                      int out_of_space__1323 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1323, now);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }


                      // 2013
                      if (false == ((out_of_space__1323) & (0u == number_of_freed_flows__58))) {

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_2 = 0u;
                        vector_locks_borrow(vector_5, new_index__1323, (void**)(&vector_value_out_2));
                        vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                        vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                        vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                        vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                        if (!write_state_ptr[0]) {
                          write_attempt_ptr[0] = 1;
                          return 1;
                        }

                        uint8_t* vector_value_out_3 = 0u;
                        vector_locks_borrow(vector_4, new_index__1323, (void**)(&vector_value_out_3));
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
                        map_locks_put(map_2, vector_value_out_2, new_index__1323);

                        if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                          return 1;
                        }

                        vector_locks_return(vector_5, new_index__1323, vector_value_out_2);
                        vector_locks_return(vector_4, new_index__1323, vector_value_out_3);
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
                      dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          }

                          // 2016
                          else {
                            vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                            return 1;
                          } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                        }

                        // 2017
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                      }

                      // 2018
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1386 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 2019
                  // 2020
                  if (0u == map_has_this_key__1386) {
                    uint32_t new_index__1389;
                    int out_of_space__1389 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1389, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 2019
                    if (false == ((out_of_space__1389) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_5, new_index__1389, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_4, new_index__1389, (void**)(&vector_value_out_3));
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
                      map_locks_put(map_2, vector_value_out_2, new_index__1389);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__1389, vector_value_out_2);
                      vector_locks_return(vector_4, new_index__1389, vector_value_out_3);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 2022
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 2023
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 2024
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__1452 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                // 2025
                // 2026
                if (0u == map_has_this_key__1452) {
                  uint32_t new_index__1455;
                  int out_of_space__1455 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1455, now);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }


                  // 2025
                  if (false == ((out_of_space__1455) & (0u == number_of_freed_flows__58))) {

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_5, new_index__1455, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_4, new_index__1455, (void**)(&vector_value_out_3));
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
                    map_locks_put(map_2, vector_value_out_2, new_index__1455);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }

                    vector_locks_return(vector_5, new_index__1455, vector_value_out_2);
                    vector_locks_return(vector_4, new_index__1455, vector_value_out_3);
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
                  dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_2 = 0u;
                  vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      }

                      // 2028
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 2029
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 2030
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
          vector_locks_return(vector, map_value_out, vector_value_out);
          uint8_t map_key_1[4];
          map_key_1[0u] = ipv4_header_1->src_addr & 0xff;
          map_key_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
          map_key_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
          map_key_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;
          int map_value_out_1;
          int map_has_this_key__1518 = map_locks_get(map_1, map_key_1, &map_value_out_1);

          // 2031
          // 2032
          // 2033
          // 2034
          // 2035
          // 2036
          // 2037
          if (0u == map_has_this_key__1518) {
            uint32_t new_index__1521;
            int out_of_space__1521 = !dchain_locks_allocate_new_index(dchain_1, &new_index__1521, now);

            if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
              return 1;
            }


            // 2031
            // 2032
            // 2033
            // 2034
            // 2035
            // 2036
            if (false == ((out_of_space__1521) & (0u == number_of_freed_flows__57))) {

              if (!write_state_ptr[0]) {
                write_attempt_ptr[0] = 1;
                return 1;
              }

              uint8_t* vector_value_out_1 = 0u;
              vector_locks_borrow(vector_3, new_index__1521, (void**)(&vector_value_out_1));
              vector_value_out_1[0u] = ipv4_header_1->src_addr & 0xff;
              vector_value_out_1[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              vector_value_out_1[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              vector_value_out_1[3u] = ((ipv4_header_1->src_addr & 4244635647u) >> 24ul) & 0xff;

              if (!write_state_ptr[0]) {
                write_attempt_ptr[0] = 1;
                return 1;
              }

              uint8_t* vector_value_out_2 = 0u;
              vector_locks_borrow(vector_2, new_index__1521, (void**)(&vector_value_out_2));
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
              map_locks_put(map_1, vector_value_out_1, new_index__1521);

              if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                return 1;
              }

              vector_locks_return(vector_3, new_index__1521, vector_value_out_1);
              vector_locks_return(vector_2, new_index__1521, vector_value_out_2);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__1529 = map_locks_get(map_2, map_key_2, &map_value_out_2);

              // 2031
              // 2032
              if (0u == map_has_this_key__1529) {
                uint32_t new_index__1532;
                int out_of_space__1532 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1532, now);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }


                // 2031
                if (false == ((out_of_space__1532) & (0u == number_of_freed_flows__58))) {

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_3 = 0u;
                  vector_locks_borrow(vector_5, new_index__1532, (void**)(&vector_value_out_3));
                  vector_value_out_3[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_3[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_3[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_3[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_4 = 0u;
                  vector_locks_borrow(vector_4, new_index__1532, (void**)(&vector_value_out_4));
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
                  map_locks_put(map_2, vector_value_out_3, new_index__1532);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }

                  vector_locks_return(vector_5, new_index__1532, vector_value_out_3);
                  vector_locks_return(vector_4, new_index__1532, vector_value_out_4);
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
                dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_3 = 0u;
                vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_3));
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
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    }

                    // 2034
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                      return 1;
                    } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 2035
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
                    return 1;
                  } // !((vector_value_out_3[0ul] + ((625ul * (now - vector_value_out_3[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 2036
                else {
                  vector_locks_return(vector_4, map_value_out_2, vector_value_out_3);
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
            dchain_locks_rejuvenate_index(dchain_1, map_value_out_1, now);

            if (!write_state_ptr[0]) {
              write_attempt_ptr[0] = 1;
              return 1;
            }

            uint8_t* vector_value_out_1 = 0u;
            vector_locks_borrow(vector_2, map_value_out_1, (void**)(&vector_value_out_1));
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1610 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 2038
                  // 2039
                  if (0u == map_has_this_key__1610) {
                    uint32_t new_index__1613;
                    int out_of_space__1613 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1613, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 2038
                    if (false == ((out_of_space__1613) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_5, new_index__1613, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_4, new_index__1613, (void**)(&vector_value_out_3));
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
                      map_locks_put(map_2, vector_value_out_2, new_index__1613);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__1613, vector_value_out_2);
                      vector_locks_return(vector_4, new_index__1613, vector_value_out_3);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 2041
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 2042
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 2043
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                  vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                  uint8_t map_key_2[4];
                  map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                  map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                  int map_value_out_2;
                  int map_has_this_key__1676 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                  // 2044
                  // 2045
                  if (0u == map_has_this_key__1676) {
                    uint32_t new_index__1679;
                    int out_of_space__1679 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1679, now);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }


                    // 2044
                    if (false == ((out_of_space__1679) & (0u == number_of_freed_flows__58))) {

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_2 = 0u;
                      vector_locks_borrow(vector_5, new_index__1679, (void**)(&vector_value_out_2));
                      vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                      vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                      vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                      vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                      if (!write_state_ptr[0]) {
                        write_attempt_ptr[0] = 1;
                        return 1;
                      }

                      uint8_t* vector_value_out_3 = 0u;
                      vector_locks_borrow(vector_4, new_index__1679, (void**)(&vector_value_out_3));
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
                      map_locks_put(map_2, vector_value_out_2, new_index__1679);

                      if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                        return 1;
                      }

                      vector_locks_return(vector_5, new_index__1679, vector_value_out_2);
                      vector_locks_return(vector_4, new_index__1679, vector_value_out_3);
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
                    dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        }

                        // 2047
                        else {
                          vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                          return 1;
                        } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                      }

                      // 2048
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                    }

                    // 2049
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
                vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
                uint8_t map_key_2[4];
                map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
                map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
                int map_value_out_2;
                int map_has_this_key__1742 = map_locks_get(map_2, map_key_2, &map_value_out_2);

                // 2050
                // 2051
                if (0u == map_has_this_key__1742) {
                  uint32_t new_index__1745;
                  int out_of_space__1745 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1745, now);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }


                  // 2050
                  if (false == ((out_of_space__1745) & (0u == number_of_freed_flows__58))) {

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_2 = 0u;
                    vector_locks_borrow(vector_5, new_index__1745, (void**)(&vector_value_out_2));
                    vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                    vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                    vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                    vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                    if (!write_state_ptr[0]) {
                      write_attempt_ptr[0] = 1;
                      return 1;
                    }

                    uint8_t* vector_value_out_3 = 0u;
                    vector_locks_borrow(vector_4, new_index__1745, (void**)(&vector_value_out_3));
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
                    map_locks_put(map_2, vector_value_out_2, new_index__1745);

                    if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                      return 1;
                    }

                    vector_locks_return(vector_5, new_index__1745, vector_value_out_2);
                    vector_locks_return(vector_4, new_index__1745, vector_value_out_3);
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
                  dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_2 = 0u;
                  vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      }

                      // 2053
                      else {
                        vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                        return 1;
                      } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                    }

                    // 2054
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                  }

                  // 2055
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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
              vector_locks_return(vector_2, map_value_out_1, vector_value_out_1);
              uint8_t map_key_2[4];
              map_key_2[0u] = ipv4_header_1->src_addr & 0xff;
              map_key_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
              map_key_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
              map_key_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;
              int map_value_out_2;
              int map_has_this_key__1808 = map_locks_get(map_2, map_key_2, &map_value_out_2);

              // 2056
              // 2057
              if (0u == map_has_this_key__1808) {
                uint32_t new_index__1811;
                int out_of_space__1811 = !dchain_locks_allocate_new_index(dchain_2, &new_index__1811, now);

                if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                  return 1;
                }


                // 2056
                if (false == ((out_of_space__1811) & (0u == number_of_freed_flows__58))) {

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_2 = 0u;
                  vector_locks_borrow(vector_5, new_index__1811, (void**)(&vector_value_out_2));
                  vector_value_out_2[0u] = ipv4_header_1->src_addr & 0xff;
                  vector_value_out_2[1u] = (ipv4_header_1->src_addr >> 8) & 0xff;
                  vector_value_out_2[2u] = (ipv4_header_1->src_addr >> 16) & 0xff;
                  vector_value_out_2[3u] = (ipv4_header_1->src_addr >> 24) & 0xff;

                  if (!write_state_ptr[0]) {
                    write_attempt_ptr[0] = 1;
                    return 1;
                  }

                  uint8_t* vector_value_out_3 = 0u;
                  vector_locks_borrow(vector_4, new_index__1811, (void**)(&vector_value_out_3));
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
                  map_locks_put(map_2, vector_value_out_2, new_index__1811);

                  if (write_attempt_ptr[0] && (!write_state_ptr[0])) {
                    return 1;
                  }

                  vector_locks_return(vector_5, new_index__1811, vector_value_out_2);
                  vector_locks_return(vector_4, new_index__1811, vector_value_out_3);
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
                dchain_locks_rejuvenate_index(dchain_2, map_value_out_2, now);

                if (!write_state_ptr[0]) {
                  write_attempt_ptr[0] = 1;
                  return 1;
                }

                uint8_t* vector_value_out_2 = 0u;
                vector_locks_borrow(vector_4, map_value_out_2, (void**)(&vector_value_out_2));
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
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    }

                    // 2059
                    else {
                      vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                      return 1;
                    } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= packet_length)

                  }

                  // 2060
                  else {
                    vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
                    return 1;
                  } // !((vector_value_out_2[0ul] + ((625ul * (now - vector_value_out_2[8ul])) / 1000000000ul)) <= 3750000000ul)

                }

                // 2061
                else {
                  vector_locks_return(vector_4, map_value_out_2, vector_value_out_2);
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

