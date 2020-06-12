#pragma once

#include "./libvig_access.h"
#include <z3.h>
#include <r3s.h>

typedef struct {
  unsigned first_access_id;
  unsigned second_access_id;
  char *query;
  unsigned query_sz;
} smt_t;

typedef struct {
  Z3_ast     select;
  int        p_count;

  union {
    unsigned index;
    dep_t    pf;
  };

  // if true, union in a processed pf (R3S_pf_t); else, index
  bool processed;
} pfast_t;

bool pfast_eq(Z3_context ctx, pfast_t pfast1, pfast_t pfast2);

typedef struct {
  pfast_t *pfs;
  size_t   sz;
} pfasts_t;

void pfasts_init(pfasts_t *pfasts);
void pfasts_destroy(pfasts_t *pfasts);
void pfasts_append_unique(Z3_context ctx, pfasts_t *pfasts, pfast_t pfast);
void pfasts_sort(pfasts_t *pfasts);

typedef struct {
  libvig_access_t *first;
  libvig_access_t *second;
  Z3_ast          cnstr;
  pfasts_t        pfs;
} constraint_t;

typedef struct {
  constraint_t *cnstrs;
  size_t       sz;
} constraints_t;

void constraints_init(constraints_t *cnstrs);
void constraints_append(constraints_t *cnstrs, libvig_accesses_t accesses,
                        smt_t smt, Z3_context ctx);
void constraints_destroy(constraints_t *cnstrs);
void constraints_process_pfs(constraints_t *cnstrs, libvig_accesses_t accesses);
