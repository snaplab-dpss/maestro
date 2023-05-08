#include "adder_config.h"
#include "nf-util.h"
#include "nf.h"

#ifdef KLEE_VERIFICATION
#include "lib/models/str-descr.h"
#endif // KLEE_VERIFICATION

struct nf_config config;

bool nf_init(void) { return true; }

struct custom_chunk_t {
  uint32_t a;
  uint32_t b;
  uint32_t c;
};

#ifdef KLEE_VERIFICATION
static struct str_field_descr custom_chunk_fields[] = {
  { offsetof(struct custom_chunk_t, a), sizeof(uint32_t), 0, "a" },
  { offsetof(struct custom_chunk_t, b), sizeof(uint32_t), 0, "b" },
  { offsetof(struct custom_chunk_t, c), sizeof(uint32_t), 0, "c" },
};
#endif

struct custom_chunk_t *parse_custom_chunk(uint8_t **buffer) {
  uint16_t unread_len = packet_get_unread_length(buffer);
  size_t required_size = sizeof(struct custom_chunk_t);

  if (unread_len < required_size) {
    return NULL;
  }

#ifdef KLEE_VERIFICATION
  CHUNK_LAYOUT(buffer, custom_chunk_t, custom_chunk_fields);
#endif

  void *hdr = nf_borrow_next_chunk(buffer, sizeof(struct custom_chunk_t));
  return (struct custom_chunk_t *)hdr;
}

int nf_process(uint16_t device, uint8_t **buffer, uint16_t packet_length,
               vigor_time_t now, struct rte_mbuf *mbuf) {
  // Mark now as unused, we don't care about time
  (void)now;

  struct rte_ether_hdr *rte_ether_header = nf_then_get_rte_ether_header(buffer);
  struct custom_chunk_t *our_custom_chunk = parse_custom_chunk(buffer);

  if (our_custom_chunk != NULL &&
      our_custom_chunk->a <= UINT32_MAX - our_custom_chunk->b) {
    our_custom_chunk->c = our_custom_chunk->a + our_custom_chunk->b;
  }

  uint16_t dst_device;
  if (device == config.wan_device) {
    dst_device = config.lan_device;
  } else {
    dst_device = config.wan_device;
  }

  return dst_device;
}
