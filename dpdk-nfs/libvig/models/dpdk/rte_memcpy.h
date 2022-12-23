#ifndef RTE_MEMCPY_H
#define RTE_MEMCPY_H

#include <string.h>

static void* rte_memcpy(void* dst, const void* src, size_t n) {
  // TODO: assert that dst and src don't overlap
  
  memcpy(dst, src, n);
  return dst;
}

#endif