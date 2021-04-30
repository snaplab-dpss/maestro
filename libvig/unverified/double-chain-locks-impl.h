#ifndef _DOUBLE_CHAIN_IMPL_H_INCLUDED_
#define _DOUBLE_CHAIN_IMPL_H_INCLUDED_

#include <stdbool.h>

struct dchain_locks_cell {
  int prev;
  int next;
};

// Requires the array dchain_locks_cell, large enough to fit all the range of
// possible 'index' values + 2 special values.
// Forms a two closed linked lists inside the array.
// First list represents the "free" cells. It is a single linked list.
// Initially the whole array
// (except 2 special cells holding metadata) added to the "free" list.
// Second list represents the "occupied" cells and it is double-linked,
// the order matters.
// It is supposed to store the ordered sequence, and support moving any
// element to the top.
//
// The lists are organized as follows:
//              +----+   +---+   +-------------------+   +-----
//              |    V   |   V   |                   V   |
//  [. + .][    .]  {    .} {    .} {. + .} {. + .} {    .} ....
//   ^   ^                           ^   ^   ^   ^
//   |   |                           |   |   |   |
//   |   +---------------------------+   +---+   +-------------
//   +---------------------------------------------------------
//
// Where {    .} is an "free" list cell, and {. + .} is an "alloc" list cell,
// and dots represent prev/next fields.
// [] - denote the special cells - the ones that are always kept in the
// corresponding lists.
// Empty "alloc" and "free" lists look like this:
//
//   +---+   +---+
//   V   V   V   |
//  [. + .] [    .]
//
// , i.e. cells[0].next == 0 && cells[0].prev == 0 for the "alloc" list, and
// cells[1].next == 1 for the free list.
// For any cell in the "alloc" list, 'prev' and 'next' fields must be different.
// Any cell in the "free" list, in contrast, have 'prev' and 'next' equal;
// After initialization, any cell is allways on one and only one of these lists.

#define DCHAIN_RESERVED (2)

void dchain_locks_impl_init(struct dchain_locks_cell *cells, int index_range);

int dchain_locks_impl_allocate_new_index(struct dchain_locks_cell *cells,
                                         int *index);

int dchain_locks_impl_free_index(struct dchain_locks_cell *cells, int index);

int dchain_locks_impl_next(struct dchain_locks_cell *cells, int index,
                           int *next);

int dchain_locks_impl_get_oldest_index(struct dchain_locks_cell *cells,
                                       int *index);

int dchain_locks_impl_reposition_index(struct dchain_locks_cell *cells,
                                       int index, int new_prev_index);
int dchain_locks_impl_rejuvenate_index(struct dchain_locks_cell *cells,
                                       int index);

int dchain_locks_impl_is_index_allocated(struct dchain_locks_cell *cells,
                                         int index);

void dchain_locks_impl_activity_init(struct dchain_locks_cell *cells, int size);
int dchain_locks_impl_activate_index(struct dchain_locks_cell *cells,
                                     int index);
int dchain_locks_impl_deactivate_index(struct dchain_locks_cell *cells,
                                       int index);
int dchain_locks_impl_is_index_active(struct dchain_locks_cell *cells,
                                      int index);

#endif //_DOUBLE_CHAIN_LOCKS_IMPL_H_INCLUDED_
