#include <cstdint>
#include <iostream>
#include <string>

#include <benchmark/benchmark.h>

#include "gk_crypto.h"

static void BM_TimeLockPuzzle_Generating(benchmark::State &state) {
  time_lock_puzzle_ex puzzle_ex = {0x00};

  gk_crypto_init();

  for (auto _ : state) {
    gk_generate_puzzle(state.range(0), 16771207, &puzzle_ex);
  }

  gk_crypto_exit();
}
BENCHMARK(BM_TimeLockPuzzle_Generating)->DenseRange(500, 3000, 500);

BENCHMARK_MAIN();
