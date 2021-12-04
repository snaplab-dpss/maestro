#include "sketch.h"

#include <stdint.h>

const uint32_t SKETCH_SALTS[SKETCH_HASHES] = { 0xec99b144, 0x18a3b351,
                                               0x4a030346, 0x3122358b };

bool hash_eq(void *a, void *b) {
  struct hash *id1 = (struct hash *)a;
  struct hash *id2 = (struct hash *)b;

  return (id1->value == id2->value);
}

void hash_allocate(void *obj) {
  struct hash *id = (struct hash *)obj;
  id->value = 0;
}

#ifdef KLEE_VERIFICATION
struct str_field_descr hash_descrs[] = {
  { offsetof(struct hash, value), sizeof(uint32_t), 0, "value" },
};
struct nested_field_descr hash_nests[] = {};

unsigned hash_hash(void *obj) {
  klee_trace_ret();
  klee_trace_param_tagged_ptr(obj, sizeof(struct hash), "obj", "hash", TD_BOTH);
  for (int i = 0; i < sizeof(hash_descrs) / sizeof(hash_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        obj, hash_descrs[i].offset, hash_descrs[i].width, hash_descrs[i].count,
        hash_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(hash_nests) / sizeof(hash_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        obj, hash_nests[i].base_offset, hash_nests[i].offset,
        hash_nests[i].width, hash_nests[i].count, hash_nests[i].name, TD_BOTH);
  }
  return klee_int("hash_hash");
}

struct str_field_descr hash_input_descrs[] = {
  { offsetof(struct hash_input, src_ip), sizeof(uint32_t), 0, "src_ip" },
  { offsetof(struct hash_input, dst_ip), sizeof(uint32_t), 0, "dst_ip" },
};
struct nested_field_descr hash_input_nests[] = {};

void sketch_hash(void *input, uint32_t salt, void *output) {
  klee_trace_param_tagged_ptr(input, sizeof(struct hash_input), "input",
                              "hash_input", TD_BOTH);
  for (int i = 0; i < sizeof(hash_input_descrs) / sizeof(hash_input_descrs[0]);
       ++i) {
    klee_trace_param_ptr_field_arr_directed(
        input, hash_input_descrs[i].offset, hash_input_descrs[i].width,
        hash_input_descrs[i].count, hash_input_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(hash_input_nests) / sizeof(hash_input_nests[0]);
       ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        input, hash_input_nests[i].base_offset, hash_input_nests[i].offset,
        hash_input_nests[i].width, hash_input_nests[i].count,
        hash_input_nests[i].name, TD_BOTH);
  }

  klee_trace_param_u32(salt, "salt");

  klee_trace_param_tagged_ptr(output, sizeof(struct hash), "output", "hash",
                              TD_BOTH);
  for (int i = 0; i < sizeof(hash_descrs) / sizeof(hash_descrs[0]); ++i) {
    klee_trace_param_ptr_field_arr_directed(
        output, hash_descrs[i].offset, hash_descrs[i].width,
        hash_descrs[i].count, hash_descrs[i].name, TD_BOTH);
  }
  for (int i = 0; i < sizeof(hash_nests) / sizeof(hash_nests[0]); ++i) {
    klee_trace_param_ptr_nested_field_arr_directed(
        output, hash_nests[i].base_offset, hash_nests[i].offset,
        hash_nests[i].width, hash_nests[i].count, hash_nests[i].name, TD_BOTH);
  }
}

#else // KLEE_VERIFICATION

unsigned hash_hash(void *obj) {
  struct hash *id = (struct hash *)obj;

  unsigned hash = 0;
  hash = __builtin_ia32_crc32si(hash, id->value);
  return hash;
}

void sketch_hash(void *input, uint32_t salt, void *output) {
  struct hash_input *hash_input = (struct hash_input *)input;
  struct hash *hash_output = (struct hash *)output;

  hash_output->value = 0;
  hash_output->value = __builtin_ia32_crc32si(hash_output->value, salt);
  hash_output->value =
      __builtin_ia32_crc32si(hash_output->value, hash_input->src_ip);
  hash_output->value =
      __builtin_ia32_crc32si(hash_output->value, hash_input->dst_ip);
}

#endif // KLEE_VERIFICATION
