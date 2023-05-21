#ifndef _SKETCH_H_INCLUDED_
#define _SKETCH_H_INCLUDED_

#include "sketch-util.h"

#include <stdbool.h>
#include <stdint.h>

#include "lib/verified/map.h"
#include "lib/verified/vigor-time.h"

struct Sketch;

int sketch_allocate(map_key_hash *kh, uint32_t capacity, uint16_t threshold,
                    struct Sketch **sketch_out);
void sketch_compute_hashes(struct Sketch *sketch, void *k);
void sketch_refresh(struct Sketch *sketch, vigor_time_t now);
int sketch_fetch(struct Sketch *sketch);
int sketch_touch_buckets(struct Sketch *sketch, vigor_time_t now);
void sketch_expire(struct Sketch *sketch, vigor_time_t time);

#endif