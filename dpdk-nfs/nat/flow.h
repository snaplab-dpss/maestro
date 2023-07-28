#ifndef _FLOW_H_INCLUDED_
#define _FLOW_H_INCLUDED_

#include <stdint.h>

struct FlowId {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t internal_device;
  uint8_t protocol;
};

#include <stdbool.h>
#include "lib/verified/boilerplate-util.h"

#include "lib/verified/ether.h"

#include "flow.h"

#define DEFAULT_FLOWID FlowIdc(0, 0, 0, 0, 0, 0)

unsigned FlowId_hash(void* obj);
bool FlowId_eq(void* a, void* b);
void FlowId_allocate(void* obj);

#define LOG_FLOWID(obj, p)                          \
  ;                                                 \
  p("{");                                           \
  p("src_port: %d", (obj)->src_port);               \
  p("dst_port: %d", (obj)->dst_port);               \
  p("src_ip: %d", (obj)->src_ip);                   \
  p("dst_ip: %d", (obj)->dst_ip);                   \
  p("internal_device: %d", (obj)->internal_device); \
  p("protocol: %d", (obj)->protocol);               \
  p("}");

#ifdef KLEE_VERIFICATION
#include <klee/klee.h>
#include "lib/models/str-descr.h"

extern struct str_field_descr FlowId_descrs[6];
extern struct nested_field_descr FlowId_nests[0];
#endif  // KLEE_VERIFICATION

#endif  // _FLOW_H_INCLUDED_