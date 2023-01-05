#include "double-chain-locks-impl.h"

#include <rte_lcore.h>

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
