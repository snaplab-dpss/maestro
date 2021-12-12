#ifndef _CLIENT_H_INCLUDED_
#define _CLIENT_H_INCLUDED_

#include <stdbool.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/map.h"
#include "libvig/verified/vector.h"
#include "libvig/verified/double-chain.h"
#include "libvig/verified/vigor-time.h"
#include "libvig/unverified/sketch.h"

#include <stdint.h>

struct client {
  uint32_t src_ip;
  uint32_t dst_ip;
};

unsigned client_hash(void *obj);

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "libvig/models/str-descr.h"
extern struct str_field_descr client_descrs[2];
extern struct nested_field_descr client_nests[0];
#endif // KLEE_VERIFICATION

#endif //_CLIENT_H_INCLUDED_
