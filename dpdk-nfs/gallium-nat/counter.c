#include "counter.h"
#include "state.h"

void counter_allocate(void *obj) {
  struct Counter *id = (struct Counter *)obj;
  id->value = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr counter_descrs[] = {
  { offsetof(struct Counter, value), sizeof(uint32_t), 0, "value" },
};

struct nested_field_descr counter_nests[] = {};

bool counter_invariant(void *counter, int index, void *state) {
  struct Counter *c = (struct Counter *)counter;
  struct State *s = (struct State *)state;
  return c->value <= s->max_flows;
}
#endif // KLEE_VERIFICATION
