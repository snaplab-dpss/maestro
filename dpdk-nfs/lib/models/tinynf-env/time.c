#include "env/time.h"

#include "lib/models/hardware.h"

void tn_sleep_us(uint64_t microseconds) { TIME += microseconds * 1000; }
