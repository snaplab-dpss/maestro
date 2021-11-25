#ifndef _SCANNEDPORTS_GEN_H_INCLUDED_
#define _SCANNEDPORTS_GEN_H_INCLUDED_

#include <stdbool.h>

#include "libvig/verified/boilerplate-util.h"
#include "libvig/verified/ether.h"
#include "libvig/verified/vigor-time.h"

typedef uint64_t ports_bucket_t;

#define MAX_NUM_PORTS 65536
#define BUCKET_SIZE (sizeof(ports_bucket_t) * 8)
#define NUM_BUCKETS ((MAX_NUM_PORTS) / (BUCKET_SIZE))

#define BUCKET_POS(port) (((ports_bucket_t)(port)) / BUCKET_SIZE)
#define PORT_POS(port) (((ports_bucket_t)(port)) % BUCKET_SIZE)

#define PORT_FROM_BUCKETS(buckets, port)                                       \
  (((buckets)[BUCKET_POS(port)] >> (PORT_POS(port))) & 1)

struct ScannedPorts {
  uint32_t src_ip;
  ports_bucket_t buckets[NUM_BUCKETS];
  uint16_t total;
};

unsigned ScannedPorts_hash(void *obj);
bool ScannedPorts_eq(void *a, void *b);
void ScannedPorts_allocate(void *obj);

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "libvig/models/str-descr.h"

extern struct str_field_descr ScannedPorts_descrs[3];
extern struct nested_field_descr ScannedPorts_nests[0];
#endif // KLEE_VERIFICATION

#endif //_SCANNEDPORTS_GEN_H_INCLUDED_
