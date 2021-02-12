#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_common.h>
#include <rte_atomic.h>
#include <rte_pause.h>
#include <rte_lcore.h>

typedef struct {
	volatile uint8_t write_permissions[RTE_MAX_LCORE];
	volatile uint32_t pending_writes;
	rte_spinlock_t write_lock;
	int dummy;
} nf_lock_t;

static inline void
nf_lock_init(nf_lock_t *nfl)
{
	unsigned lcore_id;
	RTE_LCORE_FOREACH(lcore_id) {
		nfl->write_permissions[lcore_id] = 1;
	}
	nfl->pending_writes = 0;
	rte_spinlock_init(&nfl->write_lock);
}

static inline void
nf_lock_allow_writes(nf_lock_t *nfl) {
	unsigned lcore_id = rte_lcore_id();
	nfl->write_permissions[lcore_id] = 1;
}

static inline void
nf_lock_block_writes(nf_lock_t *nfl) {
	unsigned lcore_id = rte_lcore_id();
	// preemptive block
	nfl->write_permissions[lcore_id] = 0;

	if (!nfl->pending_writes) {
		return;
	}

	// blocked too fast, unlock and allow write
	nfl->write_permissions[lcore_id] = 1;
	while (nfl->pending_writes) {
		// prevent the compiler from removing this loop
		__asm__ __volatile__("");
	}
	nfl->write_permissions[lcore_id] = 0;
}

static inline void
nf_lock_write_lock(nf_lock_t *nfl) {
	rte_atomic32_inc((rte_atomic32_t *)(intptr_t)&nfl->pending_writes);

	// allow myself to write
	unsigned lcore_id = rte_lcore_id();
	nfl->write_permissions[lcore_id] = 1;
	int success = 0;
	while (success == 0) {
		success = 1;
		RTE_LCORE_FOREACH(lcore_id) {
			if (nfl->write_permissions[lcore_id] == 0) {
				success = 0;
				break;
			}
		}
	}
	rte_spinlock_lock(&nfl->write_lock);
}

static inline void
nf_lock_write_unlock(nf_lock_t *nfl) {
	rte_spinlock_unlock(&nfl->write_lock);
	rte_atomic32_dec((rte_atomic32_t *)(intptr_t)&nfl->pending_writes);
}

#ifdef __cplusplus
}
#endif
