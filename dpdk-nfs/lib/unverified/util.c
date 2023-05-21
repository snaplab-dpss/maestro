#include "util.h"

#include <stdint.h>

unsigned hash_obj(void *obj, int size_bytes) {
  uint8_t *bytes = (uint8_t *)obj;
  unsigned hash = 0;

  for (int i = 0; i < size_bytes; i++) {
    hash = __builtin_ia32_crc32si(hash, bytes[i]);
  }

  return hash;
}