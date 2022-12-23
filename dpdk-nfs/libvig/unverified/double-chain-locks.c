#include "double-chain-locks.h"

#include <stdlib.h>
#include <stddef.h>

#include "double-chain-locks-impl.h"

#include <rte_malloc.h>
#include <rte_lcore.h>

#ifndef NULL
#define NULL 0
#endif  // NULL

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
  if (chain_alloc == NULL) return 0;
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
