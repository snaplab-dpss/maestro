#include "double-chain-tm.h"

#include <stdlib.h>
#include <stddef.h>

#include "double-chain-tm-impl.h"

#include <rte_malloc.h>
#include <rte_lcore.h>

#ifndef NULL
#define NULL 0
#endif  // NULL

typedef struct {
  vigor_time_t timestamp;
} __attribute__((aligned(64))) vigor_time_alligned_t;

struct DoubleChainTM {
  dchain_tm_cell_t *cells[RTE_MAX_LCORE];
  dchain_tm_cell_t *active_cells[RTE_MAX_LCORE];
  vigor_time_alligned_t *timestamps[RTE_MAX_LCORE];
  int range;
};

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
