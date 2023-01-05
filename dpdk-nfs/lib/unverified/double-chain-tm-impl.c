#include "double-chain-tm-impl.h"

#include <assert.h>

#include <rte_lcore.h>

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
