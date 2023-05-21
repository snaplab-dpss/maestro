#ifndef __FLOW_H__
#define __FLOW_H__

#include <stdbool.h>
#include <stdint.h>

#include "lib/verified/boilerplate-util.h"

struct Flow {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
};

unsigned flow_hash(void *obj);
bool flow_eq(void *a, void *b);
void flow_allocate(void *obj);

#define LOG_FLOW(obj, p)                                                       \
  p("{");                                                                      \
  p("src_addr: %d", (obj)->src_addr);                                          \
  p("dst_addr: %d", (obj)->dst_addr);                                          \
  p("src_port: %d", (obj)->src_port);                                          \
  p("dst_port: %d", (obj)->dst_port);                                          \
  p("protocol: %d", (obj)->protocol);                                          \
  p("}");

#ifdef KLEE_VERIFICATION
#include "lib/models/str-descr.h"
#include <klee/klee.h>

extern struct str_field_descr flow_descrs[5];
extern struct nested_field_descr flow_nests[0];
#endif // KLEE_VERIFICATION

#endif