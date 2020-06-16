#pragma once

#include <r3s.h>
//#include <stdbool.h>

class Dependency {
  
  private:

  unsigned offset;
  unsigned bytes;
  R3S_pf_t pf;
  bool     pf_is_set;
  char     error_descr[50];
};

class Access {

  private:

  unsigned   id;
  unsigned   device;
  unsigned   obj;
  unsigned   layer;
  unsigned   proto;
  Dependency dep;
};

/*
typedef struct {
  unsigned offset;
  unsigned bytes;    // big endian
  R3S_pf_t pf;
  bool     pf_is_set;
  char     error_descr[50];
} dep_t;

typedef struct {
  dep_t  *deps;
  size_t sz;
} deps_t;

bool dep_eq(dep_t d1, dep_t d2);
bool dep_in_array(deps_t deps, dep_t dep);
void deps_init(deps_t *deps);
void deps_destroy(deps_t *deps);
void deps_append_unique(deps_t *deps, dep_t dep);
deps_t deps_merge(deps_t deps1, deps_t deps2);

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
libvig_access_t* libvig_access_get_from_id(libvig_accesses_t *accesses, unsigned id);
void libvig_accesses_append_unique(libvig_access_t access,
                                   libvig_accesses_t *accesses);

dep_t dep_from_offset(unsigned offset, libvig_access_t access);
*/
