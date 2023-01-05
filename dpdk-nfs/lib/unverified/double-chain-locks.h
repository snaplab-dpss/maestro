#ifndef _DOUBLE_CHAIN_LOCKS_H_INCLUDED_
#define _DOUBLE_CHAIN_LOCKS_H_INCLUDED_

#include <stdint.h>
#include <stdbool.h>

#include <rte_lcore.h>
#include <rte_per_lcore.h>

#include "../verified/vigor-time.h"

RTE_DECLARE_PER_LCORE(bool, write_attempt);
RTE_DECLARE_PER_LCORE(bool, write_state);

struct DoubleChainLocks;
// Makes sure the allocator structur fits into memory, and particularly into
// 32 bit address space.
#define IRANG_LIMIT (1048576)

// kinda hacky, but makes the proof independent of vigor_time_t... sort of
#define malloc_block_time malloc_block_llongs
#define time_integer llong_integer
#define times llongs

int dchain_locks_allocate(int index_range, struct DoubleChainLocks **chain_out);

int dchain_locks_allocate_new_index(struct DoubleChainLocks *chain,
                                    int *index_out, vigor_time_t time);

int dchain_locks_rejuvenate_index(struct DoubleChainLocks *chain, int index,
                                  vigor_time_t time);

int dchain_locks_expire_one_index(struct DoubleChainLocks *chain,
                                  int *index_out, vigor_time_t time);

int dchain_locks_is_index_allocated(struct DoubleChainLocks *chain, int index);
int dchain_locks_free_index(struct DoubleChainLocks *chain, int index);

#endif //_DOUBLE_CHAIN_LOCKS_H_INCLUDED_
