#ifndef _SKETCH_H_INCLUDED_

#include "sketch-util.h"

#include <stdbool.h>
#include <stdint.h>

#include "libvig/unverified/map-locks.h"
#include "libvig/verified/vigor-time.h"

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

struct SketchLocks;

int sketch_locks_allocate(map_key_hash *kh, uint32_t capacity,
                          uint16_t threshold, struct SketchLocks **sketch_out);
void sketch_locks_compute_hashes(struct SketchLocks *sketch, void *k);
void sketch_locks_refresh(struct SketchLocks *sketch, vigor_time_t now);
int sketch_locks_fetch(struct SketchLocks *sketch);
int sketch_locks_touch_buckets(struct SketchLocks *sketch, vigor_time_t now);
void sketch_locks_expire(struct SketchLocks *sketch, vigor_time_t time);

#endif