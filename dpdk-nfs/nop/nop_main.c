#include "nop_config.h"
#include "nf.h"
#include "nf-util.h"

struct nf_config config;

bool nf_init(void) { return true; }

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  // Mark now as unused, we don't care about time
  (void)now;

  uint16_t dst_device;
  if (device == config.wan_device) {
    dst_device = config.lan_device;
  } else {
    dst_device = config.wan_device;
  }

  return dst_device;
}
