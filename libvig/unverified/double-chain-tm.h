#ifndef _DOUBLE_CHAIN_TM_H_INCLUDED_
#define _DOUBLE_CHAIN_TM_H_INCLUDED_

#include <stdint.h>

#include "../verified/vigor-time.h"

//@ #include <listex.gh>
//@ #include "stdex.gh"

struct DoubleChainTM;
typedef struct DoubleChainTM __attribute__((aligned(64))) DoubleChainTM;
// Makes sure the allocator structur fits into memory, and particularly into
// 32 bit address space.
#define IRANG_LIMIT (1048576)

// kinda hacky, but makes the proof independent of vigor_time_t... sort of
#define malloc_block_time malloc_block_llongs
#define time_integer llong_integer
#define times llongs

int dchain_tm_allocate(int index_range, DoubleChainTM **chain_out);
int dchain_tm_allocate_new_index(DoubleChainTM *chain, int *index_out,
                                 vigor_time_t time);
int dchain_tm_rejuvenate_index(DoubleChainTM *chain, int index,
                               vigor_time_t time);
int dchain_tm_expire_one_index(DoubleChainTM *chain, int *index_out,
                               vigor_time_t time);
int dchain_tm_is_index_allocated(DoubleChainTM *chain, int index);
int dchain_tm_free_index(DoubleChainTM *chain, int index);

#endif //_DOUBLE_CHAIN_TM_H_INCLUDED_