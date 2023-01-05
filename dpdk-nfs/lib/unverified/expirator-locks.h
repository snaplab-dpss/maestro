#ifndef _EXPIRATOR_LOCKS_H_INCLUDED_

#include "double-chain-locks.h"
#include "double-map-locks.h"
#include "map-locks.h"
#include "vector-locks.h"

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

int expire_items_locks(struct DoubleChainLocks *chain,
                       struct DoubleMapLocks *map, vigor_time_t time);

typedef void entry_extract_key(void *entry, void **key);
typedef void entry_pack_key(void *entry, void *key);

int expire_items_single_map_locks(struct DoubleChainLocks *chain,
                                  struct VectorLocks *vector,
                                  struct MapLocks *map, vigor_time_t time);

int expire_items_single_map_offseted_locks(struct DoubleChainLocks *chain,
                                           struct VectorLocks *vector,
                                           struct MapLocks *map,
                                           vigor_time_t time, int offset);

int expire_items_single_map_iteratively_locks(struct VectorLocks *vector,
                                              struct MapLocks *map, int start,
                                              int n_elems);
#endif
