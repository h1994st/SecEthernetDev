#include <cstdint>
#include <iostream>
#include <string>

#include <benchmark/benchmark.h>

#include "time_lock_puzzle.h"

static void BM_TimeLockSquarings(benchmark::State &state) {
  TimeLockPuzzle tlp(1000);

  for (auto _ : state) { tlp.benchmark(1); }
}
BENCHMARK(BM_TimeLockSquarings);

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

static void BM_TimeLockDecrypt(benchmark::State &state) {
  TimeLockPuzzle tlp(16771207);

  uint8_t msg[16] = {0xde, 0xad, 0xbe, 0xef};

  uint8_t enc_key[512] = {0x00};
  size_t enc_key_len = sizeof(enc_key);

  uint8_t enc_msg[16] = {0x00};
  uint8_t dec_msg[16] = {0x00};

  tlp.encrypt(1, (uint8_t *) msg, sizeof(msg), enc_msg, enc_key, &enc_key_len);

  for (auto _ : state) {
    tlp.decrypt(enc_msg, sizeof(msg), enc_key, enc_key_len, dec_msg);
  }
}
BENCHMARK(BM_TimeLockDecrypt);

BENCHMARK_MAIN();
