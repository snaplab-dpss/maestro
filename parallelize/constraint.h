#pragma once

#include "./libvig_access.h"
#include <z3.h>

typedef struct {
    unsigned first_access_id;
    unsigned second_access_id;
    char     *query;
    unsigned query_sz;
} smt_t;

typedef struct {
    libvig_access_t *first;
    libvig_access_t *second;
    Z3_ast          cnstr;
} constraint_t;

typedef struct {
    constraint_t *cnstrs;
    size_t       sz;
} constraints_t;

void constraints_init(constraints_t *cnstrs);
void constraints_append(constraints_t *cnstrs, libvig_accesses_t accesses, smt_t smt);
