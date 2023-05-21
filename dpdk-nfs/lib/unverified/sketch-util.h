#ifndef _SKETCH_UTIL_H_INCLUDED_
#define _SKETCH_UTIL_H_INCLUDED_

// Careful: SKETCH_HASHES needs to be <= SKETCH_SALTS_BANK_SIZE
#define SKETCH_HASHES 4
#define SKETCH_SALTS_BANK_SIZE 64

#include <stdint.h>

extern const uint32_t SKETCH_SALTS[SKETCH_SALTS_BANK_SIZE];

#endif