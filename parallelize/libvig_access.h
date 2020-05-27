#pragma once

#include <r3s.h>
#include <stdbool.h>

typedef struct {
  unsigned offset;
  R3S_pf_t pf;
  bool pf_is_set;
  char error_descr[50];
} dep_t;

typedef struct {
  dep_t *deps;
  size_t sz;
} deps_t;

bool dep_eq(dep_t d1, dep_t d2);
bool dep_in_array(deps_t deps, dep_t dep);
void deps_init(deps_t *deps);
void deps_destroy(deps_t *deps);
void deps_append_unique(deps_t *deps, dep_t dep);

typedef struct {
  unsigned id;
  unsigned device;
  unsigned obj;
  unsigned layer;
  unsigned proto;
  deps_t deps;
} libvig_access_t;

typedef struct {
  libvig_access_t *accesses;
  size_t sz;
} libvig_accesses_t;

bool libvig_access_eq(libvig_access_t l1, libvig_access_t l2);
bool libvig_access_in_array(libvig_access_t access, libvig_accesses_t accesses);

void libvig_accesses_init(libvig_accesses_t *accesses);
void libvig_accesses_destroy(libvig_accesses_t *accesses);
void libvig_accesses_append_unique(libvig_access_t access,
                                   libvig_accesses_t *accesses);

dep_t dep_from_offset(unsigned offset, libvig_access_t access);
