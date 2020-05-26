#include "./constraint.h"
#include <stdlib.h>

void constraints_init(constraints_t *cnstrs) {
    cnstrs->cnstrs = NULL;
    cnstrs->sz     = 0;
}

void constraints_append(constraints_t *cnstrs, libvig_accesses_t accesses, smt_t smt) {
    constraint_t    *curr;
    libvig_access_t *first, *second;

    first = second = NULL;

    // check if first access is saved
    for (unsigned i = 0; i < accesses.sz; i++) {
        if (accesses.accesses[i].id == smt.first_access_id) {
            first = &(accesses.accesses[i]);
            break;
        }
    }

    if (!first) return;

    // check if second access is saved
    for (unsigned i = 0; i < accesses.sz; i++) {
        if (accesses.accesses[i].id == smt.second_access_id) {
            second = &(accesses.accesses[i]);
            break;
        }
    }

    if (!second || first->obj != second->obj) return;

    cnstrs->sz += 1;
    cnstrs->cnstrs = (constraint_t*) realloc(
        cnstrs->cnstrs,
        sizeof(constraint_t) * (cnstrs->sz)
    );

    curr = &(cnstrs->cnstrs[cnstrs->sz - 1]);

    curr->first  = first;
    curr->second = second;

    Z3_config cfg = Z3_mk_config();
    Z3_context ctx = Z3_mk_context(cfg);
    Z3_ast ast = Z3_parse_smtlib2_string(
        ctx,
        smt.query,
        0, 0, 0,
        0, 0, 0
    );

    printf("\n");
    printf("===========================================\n");
    
    printf("smt: %s\n", smt.query);
    printf("ast: %s\n", Z3_ast_to_string(ctx, ast));

    printf("first:\n");
    printf("  id   %u\n", curr->first->id);
    for (unsigned pf = 0; pf < curr->first->deps.sz; pf++)
        if (curr->first->deps.deps[pf].pf_is_set)
            printf("  dep  %s\n", R3S_pf_to_string(curr->first->deps.deps[pf].pf));
        else
            printf("  dep  %u\n", curr->first->deps.deps[pf].offset);

    printf("second:\n");
    printf("  id   %u\n", curr->second->id);
    for (unsigned pf = 0; pf < curr->second->deps.sz; pf++)
        if (curr->second->deps.deps[pf].pf_is_set)
            printf("  dep  %s\n", R3S_pf_to_string(curr->second->deps.deps[pf].pf));
        else
            printf("  dep  %u\n", curr->second->deps.deps[pf].offset);
    
    //pf_ast_t *selects = NULL;
    //size_t sz;
    //traverse_ast_and_retrieve_selects(ctx, ast, &selects, &sz);

    printf("===========================================\n");
    printf("\n");    
}
