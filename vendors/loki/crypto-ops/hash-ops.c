#include "hash-ops.h"

void hash_process(union hash_state *state, const uint8_t *buf, size_t count) {
  keccak1600(buf, count, (uint8_t*)state);
}

void cn_fast_hash(const void*data, size_t length, char *hash) {
  union hash_state state;
  hash_process(&state, (const uint8_t *)data, length);
  memcpy(hash, &state, HASH_SIZE);
}