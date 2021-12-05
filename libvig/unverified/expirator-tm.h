#ifndef _EXPIRATOR_TM_H_INCLUDED_

#include "double-chain-tm.h"
#include "../verified/double-map.h"
#include "../verified/map.h"
#include "../verified/vector.h"

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

int expire_items_tm(struct DoubleChainTM *chain, struct DoubleMap *map,
                    vigor_time_t time);

typedef void entry_extract_key(void *entry, void **key);
typedef void entry_pack_key(void *entry, void *key);

int expire_items_single_map_tm(struct DoubleChainTM *chain,
                               struct Vector *vector, struct Map *map,
                               vigor_time_t time);

int expire_items_single_map_offseted_tm(struct DoubleChainTM *chain,
                                        struct Vector *vector, struct Map *map,
                                        vigor_time_t time, int offset);

#define expire_items_single_map_iteratively_tm                                 \
  expire_items_single_map_iteratively

#endif
