#include "expirator.h"
#include <assert.h>

int expire_items_single_map_iteratively(struct Vector *vector, struct Map *map,
                                        int start, int n_elems) {
  assert(start >= 0);
  assert(n_elems >= 0);
  void *key;
  for (int i = start; i < n_elems; i++) {
    vector_borrow(vector, i, (void **)&key);
    map_erase(map, key, (void **)&key);
    vector_return(vector, i, key);
  }
}

int expire_items_single_map_offseted(struct DoubleChain *chain,
                                     struct Vector *vector, struct Map *map,
                                     vigor_time_t time, int offset) {
  assert(offset >= 0);

  int count = 0;
  int index = -1;

  while (dchain_expire_one_index(chain, &index, time)) {
    void *key;
    vector_borrow(vector, index + offset, &key);
    map_erase(map, key, &key);
    vector_return(vector, index + offset, key);
    ++count;
  }

  return count;
}
