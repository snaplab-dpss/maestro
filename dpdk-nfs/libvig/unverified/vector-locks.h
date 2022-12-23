#ifndef _VECTOR_LOCKS_H_INCLUDED_

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

struct VectorLocks;

typedef void vector_init_elem(void *elem);

int vector_locks_allocate(int elem_size, unsigned capacity,
                    vector_init_elem *init_elem, struct VectorLocks **vector_out);
void vector_locks_borrow(struct VectorLocks *vector, int index, void **val_out);
void vector_locks_return(struct VectorLocks *vector, int index, void *value);

#endif
