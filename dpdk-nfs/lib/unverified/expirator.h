#ifndef _UNVERIFIED_EXPIRATOR_H_INCLUDED_
#define _UNVERIFIED_EXPIRATOR_H_INCLUDED_

#include "../verified/map.h"
#include "../verified/vector.h"

// The function takes "coherent" chain vector and hash map,
// and a given number of elements.
// It removes items from 0 to n_elems (inclusive) simultaneously from the vector
// and the map.
int expire_items_single_map_iteratively(struct Vector *vector, struct Map *map,
                                        int start, int n_elems);

#endif //_UNVERIFIED_EXPIRATOR_H_INCLUDED_
