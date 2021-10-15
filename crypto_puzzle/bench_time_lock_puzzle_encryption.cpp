#include <cstdint>
#include <iostream>
#include <string>

#include <benchmark/benchmark.h>

#include "time_lock_puzzle.h"

static void BM_TimeLockEncrypt(benchmark::State &state) {
  TimeLockPuzzle tlp(16771207);

  uint8_t msg[16] = {0xde, 0xad, 0xbe, 0xef};

  uint8_t enc_key[512] = {0x00};
  size_t enc_key_len = sizeof(enc_key);

  uint8_t enc_msg[16] = {0x00};
  uint8_t dec_msg[16] = {0x00};

  for (auto _ : state) {
    tlp.encrypt(
        1, (uint8_t *) msg, sizeof(msg), enc_msg, enc_key, &enc_key_len);
  }
}
BENCHMARK(BM_TimeLockEncrypt);

BENCHMARK_MAIN();
