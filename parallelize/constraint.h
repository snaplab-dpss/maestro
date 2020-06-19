#pragma once

#include <iostream>
#include <vector>
#include <string>

#include "libvig_access.h"

#include <z3.h>
#include <r3s.h>

namespace ParallelSynthesizer {

class RawConstraint {

private:

  unsigned int first_access_id;
  unsigned int second_access_id;
  std::string expression;

public:

  RawConstraint(
    const unsigned int& _first,
    const unsigned int& _second,
    const std::string& _expression
  ) : first_access_id(_first), second_access_id(_second), expression(_expression) {}
  
  const unsigned int& get_first_access_id() const { return first_access_id;  }
  const unsigned int& get_second_access_id() const { return second_access_id; }
  const std::string&  get_expression() const { return expression;       }

  friend bool operator==(const RawConstraint& lhs, const RawConstraint& rhs);
};


class PacketFieldExpression {

private:

    Z3_context ctx;
    Z3_ast expression;
    unsigned int index;

public:

    PacketFieldExpression(const Z3_context& _ctx, const Z3_ast& _expression, const unsigned int& _index)
        : ctx(_ctx), expression(_expression), index(_index) {}
    
    PacketFieldExpression(const PacketFieldExpression& pfe)
        : ctx(pfe.get_context()), expression(pfe.get_expression()), index(pfe.get_index()) {}
    
    const Z3_context& get_context() const { return ctx; }
    const Z3_ast& get_expression() const { return expression; }
    const unsigned int& get_index() const { return index; }

    friend bool operator<(const PacketFieldExpression& lhs, const PacketFieldExpression& rhs);
    
    static void add_unique_packet_field_expression(std::vector<PacketFieldExpression>& pfes, const PacketFieldExpression& pfe);
};

class Constraint {

private:

    Z3_context ctx;

    LibvigAccess first;
    LibvigAccess second;

    Z3_ast expression;
 
    std::vector< std::pair<PacketFieldExpression, R3S_pf_t> > packet_fields;

public:

  Constraint(
    const LibvigAccess& _first,
    const LibvigAccess& _second,
    const Z3_context& _ctx,
    const RawConstraint& raw_constraint
  ) : ctx(_ctx), first(_first), second(_second) {    
    expression = Z3_parse_smtlib2_string(
        ctx,
        raw_constraint.get_expression().c_str(),
        0, 0, 0, 0, 0, 0
    );
    
    std::vector<PacketFieldExpression> packet_fields_expressions;
    fill_packet_fields(expression, packet_fields_expressions);
    zip_packet_fields_expression_and_values(packet_fields_expressions);
}

private:

    void fill_packet_fields(Z3_ast& expression, std::vector<PacketFieldExpression>& pfes);
    void zip_packet_fields_expression_and_values(const std::vector<PacketFieldExpression>& pfes);

};

}

/*
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
*/
