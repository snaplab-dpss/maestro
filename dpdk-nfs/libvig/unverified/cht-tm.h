#ifndef _CHT_TM_H_INCLUDED_
#define _CHT_TM_H_INCLUDED_

#include "libvig/unverified/double-chain-tm.h"
#include "libvig/verified/vector.h"

#define MAX_CHT_HEIGHT 40000

int cht_tm_fill_cht(struct Vector *cht, uint32_t cht_height, uint32_t backend_capacity);
int cht_tm_find_preferred_available_backend(uint64_t hash, struct Vector *cht, struct DoubleChainTM *active_backends, uint32_t cht_height, uint32_t backend_capacity, int *chosen_backend);

#endif //_CHT_TM_H_INCLUDED_
