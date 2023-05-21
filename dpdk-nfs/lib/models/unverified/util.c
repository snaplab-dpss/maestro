#include "lib/unverified/util.h"

#include <klee/klee.h>
#include <stdint.h>

unsigned hash_obj(void *obj, int size_bytes) {
  klee_trace_ret();
  klee_trace_param_u64((uint64_t)obj, "obj");
  klee_trace_param_i32(size_bytes, "size");
  return klee_int("hash");
}
