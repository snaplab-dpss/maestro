#include "./constraint.h"

/*
#include <stdlib.h>
#include "string.h"
#include <assert.h>

bool pfast_eq(Z3_context ctx, pfast_t pfast1, pfast_t pfast2) {
  assert(pfast1.processed == pfast2.processed);

  if (pfast1.pf.bytes != pfast2.pf.bytes) return false;

  if (!Z3_is_eq_ast(ctx, pfast1.select, pfast2.select))
    return false;

  if (pfast1.processed) {
    return pfast1.pf.pf == pfast2.pf.pf;
  } else {
    return pfast1.index == pfast2.index;
  }
}

void pfasts_init(pfasts_t *pfasts) {
  pfasts->pfs = NULL;
  pfasts->sz = 0;
}

void pfasts_destroy(pfasts_t *pfasts) {
  if (pfasts->sz)
    free(pfasts->pfs);
}

void pfasts_append_unique(Z3_context ctx, pfasts_t *pfasts, pfast_t pfast) {
  for (unsigned i = 0; i < pfasts->sz; i++)
    if (pfast_eq(ctx, pfasts->pfs[i], pfast)) return;

  pfasts->sz++;
  pfasts->pfs = (pfast_t *)realloc(pfasts->pfs, sizeof(pfast_t) * pfasts->sz);
  pfasts->pfs[pfasts->sz - 1] = pfast;
}

void parse_symbol(Z3_context ctx, Z3_symbol symbol) {
  switch (Z3_get_symbol_kind(ctx, symbol)) {
  case Z3_INT_SYMBOL:
    printf("INT #%d", Z3_get_symbol_int(ctx, symbol));
    break;
  case Z3_STRING_SYMBOL:
    printf("STRING %s", Z3_get_symbol_string(ctx, symbol));
    break;
  default:
    printf("error\n");
    exit(1);
  }
}

bool is_select_from_chunk(Z3_context ctx, Z3_app app) {
  Z3_func_decl decl = Z3_get_app_decl(ctx, app);
  Z3_symbol name = Z3_get_decl_name(ctx, decl);

  if (strcmp(Z3_get_symbol_string(ctx, name), "select") != 0)
    return false;

  Z3_ast array_ast = Z3_get_app_arg(ctx, app, 0);

  assert(Z3_get_ast_kind(ctx, array_ast) == Z3_APP_AST);

  Z3_app array_app = Z3_to_app(ctx, array_ast);
  Z3_func_decl array_decl = Z3_get_app_decl(ctx, array_app);
  Z3_symbol array_name = Z3_get_decl_name(ctx, array_decl);

  if (strncmp(Z3_get_symbol_string(ctx, array_name), "packet_chunks", strlen("packet_chunks")) != 0)
    return false;

  return true;
}

void traverse_ast_and_retrieve_selects(Z3_context ctx, Z3_ast ast,
                                       pfasts_t *selects) {
  if (Z3_get_ast_kind(ctx, ast) != Z3_APP_AST)
    return;

  Z3_app app = Z3_to_app(ctx, ast);
  Z3_func_decl decl = Z3_get_app_decl(ctx, app);

  Z3_symbol name = Z3_get_decl_name(ctx, decl);

  if (is_select_from_chunk(ctx, app)) {
    Z3_ast index_ast = Z3_get_app_arg(ctx, app, 1);
    assert(Z3_get_ast_kind(ctx, index_ast) == Z3_NUMERAL_AST);

    Z3_sort index_sort = Z3_get_sort(ctx, index_ast);
    pfast_t select;

    select.processed  = false;
    select.select     = ast;
    Z3_get_numeral_uint(ctx, index_ast, &(select.index));
    Z3_inc_ref(ctx, index_ast);
    pfasts_append_unique(ctx, selects, select);

    return;
  }
  
  unsigned num_fields = Z3_get_app_num_args(ctx, app);
  for (unsigned i = 0; i < num_fields; i++) {
    traverse_ast_and_retrieve_selects(ctx, Z3_get_app_arg(ctx, app, i),
                                      selects);
  }
}

void constraints_init(constraints_t *cnstrs) {
  cnstrs->cnstrs = NULL;
  cnstrs->sz = 0;
}

void constraints_append(constraints_t *cnstrs, libvig_accesses_t accesses,
                        smt_t smt, Z3_context ctx) {
  constraint_t *curr;
  libvig_access_t *first, *second;

  first = second = NULL;

  // check if first access is saved
  for (unsigned i = 0; i < accesses.sz; i++) {
    if (accesses.accesses[i].id == smt.first_access_id) {
      first = &(accesses.accesses[i]);
      break;
    }
  }

  if (!first)
    return;

  // check if second access is saved
  for (unsigned i = 0; i < accesses.sz; i++) {
    if (accesses.accesses[i].id == smt.second_access_id) {
      second = &(accesses.accesses[i]);
      break;
    }
  }

  if (!second || first->obj != second->obj)
    return;

  cnstrs->sz += 1;
  cnstrs->cnstrs = (constraint_t *)realloc(cnstrs->cnstrs,
                                           sizeof(constraint_t) * (cnstrs->sz));

  curr = &(cnstrs->cnstrs[cnstrs->sz - 1]);

  curr->first = first;
  curr->second = second;

  Z3_ast ast = Z3_parse_smtlib2_string(ctx, smt.query, 0, 0, 0, 0, 0, 0);

  curr->cnstr = ast;
  pfasts_init(&(curr->pfs));

  traverse_ast_and_retrieve_selects(ctx, ast, &(curr->pfs));
}

void constraints_destroy(constraints_t *cnstrs) {
  if (cnstrs->sz == 0)
    return;

  for (unsigned i = 0; i < cnstrs->sz; i++) {
    pfasts_destroy(&(cnstrs->cnstrs[i].pfs));
  }
}

void pfasts_sort(pfasts_t *pfasts) {
  bool change;

  if (pfasts->sz <= 1) return;

  change = true;
  while (change) {
    change = false;

    for (unsigned i = 0; i < pfasts->sz - 1; i++) {
      assert(!pfasts->pfs[i].processed && "ERROR: Trying to sort a processed pfasts");

      if (pfasts->pfs[i].index >= pfasts->pfs[i+1].index)
        continue;
      
      pfast_t tmp;
      
      tmp              = pfasts->pfs[i];
      pfasts->pfs[i]   = pfasts->pfs[i+1];
      pfasts->pfs[i+1] = tmp;

      change = true;
    }
  }
}

void constraints_process_pfs(constraints_t *cnstrs, libvig_accesses_t accesses) {
  for (int i = 0; i < cnstrs->sz; i++) {
    pfasts_sort(&(cnstrs->cnstrs[i].pfs));

    deps_t merge = deps_merge(
      cnstrs->cnstrs[i].first->deps,
      cnstrs->cnstrs[i].second->deps
    );

    // FIXME: this is awfull. Try to find a better way to associate select ast's to packet fields

    unsigned m = 0;
    bool inc = false;
    int p_count = 0;
    for (unsigned j = 0; j < cnstrs->cnstrs[i].pfs.sz; j++) {
      inc = j < cnstrs->cnstrs[i].pfs.sz - 1 &&
        (cnstrs->cnstrs[i].pfs.pfs[j].index != cnstrs->cnstrs[i].pfs.pfs[j+1].index);
      
      assert(m < merge.sz);
      cnstrs->cnstrs[i].pfs.pfs[j].pf        = merge.deps[m];
      cnstrs->cnstrs[i].pfs.pfs[j].processed = true;
      cnstrs->cnstrs[i].pfs.pfs[j].p_count   = p_count++;

      if (inc) {
        p_count = 0;
        m++;
      }

      inc = false;
    }

    deps_destroy(&merge);
  }
}
*/
