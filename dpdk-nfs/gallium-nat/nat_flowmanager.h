#ifndef _FLOWMANAGER_H__
#define _FLOWMANAGER_H__

#include <stdbool.h>
#include <stdint.h>

#include "state.h"

#include "lib/verified/vigor-time.h"

bool allocate_flow(struct State *manager, struct Flow *flow,
                   uint16_t *external_port);
bool internal_get(struct State *manager, struct Flow *flow,
                  uint16_t *external_port);
bool external_get(struct State *manager, uint16_t external_port,
                  struct Flow *out_flow);
#endif
