#ifndef _MAP_LOCKS_H_INCLUDED_

#include "../verified/map-util.h"

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

struct MapLocks;

int map_locks_allocate(map_keys_equality *keq, map_key_hash *khash, unsigned capacity,
                 struct MapLocks **map_out);
int map_locks_get(struct MapLocks *map, void *key, int *value_out);
void map_locks_put(struct MapLocks *map, void *key, int value);
void map_locks_erase(struct MapLocks *map, void *key, void **trash);
unsigned map_locks_size(struct MapLocks *map);

#endif
