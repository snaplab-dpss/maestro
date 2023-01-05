#include <stdlib.h>
#include <stdint.h>

#include "vector-locks.h"

#include <rte_malloc.h>

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
  if (vector_alloc == 0) return 0;
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
