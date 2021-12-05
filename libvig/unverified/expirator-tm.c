#include "expirator-tm.h"

#include <assert.h>
#include <stdbool.h>

int expire_items_tm(struct DoubleChainTM *chain, struct DoubleMap *map,
                    vigor_time_t time) {
  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    dmap_erase(map, index);
    ++count;
  }

  return count;
}

int expire_items_single_map_tm(struct DoubleChainTM *chain,
                               struct Vector *vector, struct Map *map,
                               vigor_time_t time) {
  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    void *key;
    vector_borrow(vector, index, &key);
    map_erase(map, key, &key);
    vector_return(vector, index, key);
    ++count;
  }

  return count;
}

int expire_items_single_map_offseted_tm(struct DoubleChainTM *chain,
                                        struct Vector *vector, struct Map *map,
                                        vigor_time_t time, int offset) {
  assert(offset >= 0);

  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    void *key;
    vector_borrow(vector, index + offset, &key);
    map_erase(map, key, &key);
    vector_return(vector, index + offset, key);
    ++count;
  }

  return count;
}
