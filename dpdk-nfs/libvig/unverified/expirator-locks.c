#include "expirator-locks.h"

#include <assert.h>
#include <stdbool.h>

int expire_items_locks(struct DoubleChainLocks *chain,
                       struct DoubleMapLocks *map, vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  int count = 0;
  int index = -1;

  while (dchain_locks_expire_one_index(chain, &index, time)) {
    if (!*write_state_ptr) {
      *write_attempt_ptr = true;
      return 1;
    }

    dmap_locks_erase(map, index);
    ++count;
  }

  return count;
}

int expire_items_single_map_locks(struct DoubleChainLocks *chain,
                                  struct VectorLocks *vector,
                                  struct MapLocks *map, vigor_time_t time) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  int count = 0;
  int index = -1;

  while (dchain_locks_expire_one_index(chain, &index, time)) {
    if (!*write_state_ptr) {
      *write_attempt_ptr = true;
      return 1;
    }

    void *key;
    vector_locks_borrow(vector, index, &key);
    map_locks_erase(map, key, &key);
    vector_locks_return(vector, index, key);
    ++count;
  }

  return count;
}

int expire_items_single_map_offseted_locks(struct DoubleChainLocks *chain,
                                           struct VectorLocks *vector,
                                           struct MapLocks *map,
                                           vigor_time_t time, int offset) {
  assert(offset >= 0);

  int count = 0;
  int index = -1;

  while (dchain_locks_expire_one_index(chain, &index, time)) {
    void *key;
    vector_locks_borrow(vector, index + offset, &key);
    map_locks_erase(map, key, &key);
    vector_locks_return(vector, index + offset, key);
    ++count;
  }

  return count;
}

int expire_items_single_map_iteratively_locks(struct VectorLocks *vector,
                                              struct MapLocks *map, int start,
                                              int n_elems) {
  bool *write_attempt_ptr = &RTE_PER_LCORE(write_attempt);
  bool *write_state_ptr = &RTE_PER_LCORE(write_state);

  if (n_elems != 0 && !*write_state_ptr) {
    *write_attempt_ptr = true;
    return 1;
  }

  assert(start >= 0);
  assert(n_elems >= 0);
  void *key;
  for (int i = start; i < n_elems; i++) {
    vector_locks_borrow(vector, i, (void **)&key);
    map_locks_erase(map, key, (void **)&key);
    vector_locks_return(vector, i, key);
  }
}
