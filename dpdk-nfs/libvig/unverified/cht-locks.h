#ifndef _CHT_LOCKS_H_INCLUDED_
#define _CHT_LOCKS_H_INCLUDED_

#include "libvig/unverified/double-chain-locks.h"
#include "libvig/unverified/vector-locks.h"

#define MAX_CHT_HEIGHT 40000

int cht_locks_fill_cht(struct VectorLocks *cht, uint32_t cht_height, uint32_t backend_capacity);
int cht_locks_find_preferred_available_backend(uint64_t hash, struct VectorLocks *cht, struct DoubleChainLocks *active_backends, uint32_t cht_height, uint32_t backend_capacity, int *chosen_backend);

#endif //_CHT_LOCKS_H_INCLUDED_
