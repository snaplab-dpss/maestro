#include "expirator-tm.h"

#include <assert.h>
#include <stdbool.h>

int expire_items_tm(struct DoubleChainTM *chain, struct DoubleMap *map,
                    vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    if (!*write_state_ptr) {
      *write_attempt_ptr = true;
      return 1;
    }

    dmap_erase(map, index);
    ++count;
  }

  return count;
}

int expire_items_single_map_tm(struct DoubleChainTM *chain,
                               struct Vector *vector, struct Map *map,
                               vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  int count = 0;
  int index = -1;

  while (dchain_tm_expire_one_index(chain, &index, time)) {
    if (!*write_state_ptr) {
      *write_attempt_ptr = true;
      return 1;
    }

    void *key;
    vector_borrow(vector, index, &key);
    map_erase(map, key, &key);
    vector_return(vector, index, key);
    ++count;
  }

  return count;
}
