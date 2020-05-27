#include "./libvig_access.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

bool libvig_access_eq(libvig_access_t l1, libvig_access_t l2) {
  if (l1.device != l2.device)
    return false;
  if (l1.obj != l2.obj)
    return false;
  if (l1.layer != l2.layer)
    return false;
  if (l1.proto != l2.proto)
    return false;
  if (l1.deps.sz != l2.deps.sz)
    return false;

  for (unsigned j = 0; j < l1.deps.sz; j++)
    if (!dep_eq(l1.deps.deps[j], l2.deps.deps[j]))
      return false;

  return true;
}

bool libvig_access_in_array(libvig_access_t access,
                            libvig_accesses_t accesses) {
  for (unsigned i = 0; i < accesses.sz; i++)
    if (libvig_access_eq(access, accesses.accesses[i]))
      return true;
  return false;
}

void libvig_accesses_init(libvig_accesses_t *accesses) {
  accesses->accesses = NULL;
  accesses->sz = 0;
}

void libvig_accesses_destroy(libvig_accesses_t *accesses) {
  if (accesses->sz == 0)
    return;
  for (unsigned acc = 0; acc < accesses->sz; acc++)
    deps_destroy(&(accesses->accesses[acc].deps));
  free(accesses->accesses);
}

void libvig_accesses_append_unique(libvig_access_t access,
                                   libvig_accesses_t *accesses) {
  libvig_access_t *curr;

  if (libvig_access_in_array(access, *accesses))
    return;

  accesses->sz += 1;
  accesses->accesses = (libvig_access_t *)realloc(
      accesses->accesses, sizeof(libvig_access_t) * (accesses->sz));

  curr = &(accesses->accesses[accesses->sz - 1]);

  memcpy(curr, &access, sizeof(libvig_access_t));
}

bool dep_eq(dep_t d1, dep_t d2) {
  return (d1.pf_is_set == d2.pf_is_set) && (!d1.pf_is_set || (d1.pf == d2.pf));
}

dep_t dep_from_offset(unsigned offset, libvig_access_t access) {
  dep_t dep;

  dep.offset = offset;
  dep.pf_is_set = false;
  dep.error_descr[0] = 0;

  // IPv4
  if (access.layer == 3 && access.proto == 0x0800) {

    if (offset == 9) {
      sprintf(dep.error_descr, "IPv4 protocol");
    } else if (offset >= 12 && offset <= 15) {
      dep.pf = R3S_PF_IPV4_SRC;
      dep.pf_is_set = true;
    } else if (offset >= 16 && offset <= 19) {
      dep.pf = R3S_PF_IPV4_DST;
      dep.pf_is_set = true;
    } else if (offset >= 20) {
      sprintf(dep.error_descr, "IPv4 options");
    } else {
      sprintf(dep.error_descr, "Unknown IPv4 field at byte %u\n", dep.offset);
    }
  }

  // IPv6
  else if (access.layer == 3 && access.proto == 0x86DD) {

  }

  // VLAN
  else if (access.layer == 3 && access.proto == 0x8100) {

  }

  // TCP
  else if (access.layer == 4 && access.proto == 0x06) {
    if (offset <= 1) {
      dep.pf = R3S_PF_TCP_SRC;
      dep.pf_is_set = true;
    } else if (offset >= 2 && offset <= 3) {
      dep.pf = R3S_PF_TCP_DST;
      dep.pf_is_set = true;
    } else {
      sprintf(dep.error_descr, "Unknown TCP field at byte %u\n", dep.offset);
    }
  }

  // UDP
  else if (access.layer == 4 && access.proto == 0x11) {
    if (offset <= 1) {
      dep.pf = R3S_PF_UDP_SRC;
      dep.pf_is_set = true;
    } else if (offset >= 2 && offset <= 3) {
      dep.pf = R3S_PF_UDP_DST;
      dep.pf_is_set = true;
    } else {
      sprintf(dep.error_descr, "Unknown UDP field at byte %u\n", dep.offset);
    }
  }

  return dep;
}

bool dep_in_array(deps_t deps, dep_t dep) {
  for (unsigned i = 0; i < deps.sz; i++)
    if ((dep.pf_is_set == deps.deps[i].pf_is_set) &&
        (!dep.pf_is_set || (dep.pf == deps.deps[i].pf)))
      return true;
  return false;
}

void deps_append_unique(deps_t *deps, dep_t dep) {
  if (dep_in_array(*deps, dep))
    return;

  deps->sz++;
  deps->deps = (dep_t *)realloc(deps->deps, sizeof(dep_t) * deps->sz);
  deps->deps[deps->sz - 1] = dep;
}

void deps_init(deps_t *deps) {
  deps->deps = NULL;
  deps->sz = 0;
}

void deps_destroy(deps_t *deps) {
  if (deps->sz)
    free(deps->deps);
}
