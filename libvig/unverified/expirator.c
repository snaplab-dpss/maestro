#include "expirator.h"
#include <assert.h>

int expire_items_single_map_iteratively(struct Vector *vector, struct Map *map,
                                        int n_elems) {
  assert(n_elems >= 0);
  void *key;
  for (int i = 0; i < n_elems; i++) {
    vector_borrow(vector, i, (void **)&key);
    map_erase(map, key, (void **)&key);
    vector_return(vector, i, key);
  }
}
