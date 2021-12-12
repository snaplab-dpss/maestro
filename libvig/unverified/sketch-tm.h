#ifndef _SKETCH_H_INCLUDED_

#include "sketch-util.h"

#include <stdbool.h>
#include <stdint.h>

#include "libvig/verified/map.h"
#include "libvig/verified/vigor-time.h"

#include <rte_lcore.h>
#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

struct SketchTM;

int sketch_tm_allocate(map_key_hash *kh, uint32_t capacity, uint16_t threshold,
                       struct SketchTM **sketch_out);
void sketch_tm_compute_hashes(struct SketchTM *sketch, void *k);
void sketch_tm_refresh(struct SketchTM *sketch, vigor_time_t now);
int sketch_tm_fetch(struct SketchTM *sketch);
int sketch_tm_touch_buckets(struct SketchTM *sketch, vigor_time_t now);
void sketch_tm_expire(struct SketchTM *sketch, vigor_time_t time);

#endif