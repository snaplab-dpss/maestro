#ifndef __FLOW_H__
#define __FLOW_H__

#include <stdint.h>
#include <stdbool.h>

#include "lib/verified/boilerplate-util.h"

struct Flow {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t device;
  uint8_t proto;
};

unsigned flow_hash(void* obj);
bool flow_eq(void* a, void* b);
void flow_allocate(void* obj);

#ifdef KLEE_VERIFICATION
#  include <klee/klee.h>
#  include "lib/models/str-descr.h"

extern struct str_field_descr flow_descrs[6];
extern struct nested_field_descr flow_nests[0];
#endif//KLEE_VERIFICATION

#endif