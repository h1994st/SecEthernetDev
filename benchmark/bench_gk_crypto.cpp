#include <cstdint>
#include <iostream>
#include <string>

#include <benchmark/benchmark.h>

#include "gk_crypto.h"

static void BM_TimeLockPuzzle_Squaring(benchmark::State &state) {
  int ret;
  for (auto _ : state) {
    // 1000 times squaring operations
    ret = gk_benchmark_puzzle(1000);
    if (ret != 0) {
      state.SkipWithError("Failed to benchmark the puzzle!");
      break;
    }
  }
}
BENCHMARK(BM_TimeLockPuzzle_Squaring);

static void BM_TimeLockPuzzle_Generating(benchmark::State &state) {
  int ret;
  time_lock_puzzle_ex puzzle_ex = {0x00};

  gk_crypto_init();

  for (auto _ : state) {
    ret = gk_generate_puzzle(state.range(0), 56392, &puzzle_ex);
    if (ret != 0) {
      state.SkipWithError("Failed to generate the puzzle!");
      break;
    }
  }

  gk_crypto_exit();
}
BENCHMARK(BM_TimeLockPuzzle_Generating)->DenseRange(100, 1000, 100);

static void BM_TimeLockPuzzle_Solving(benchmark::State &state) {
  int err;
  uint64_t ans;
  time_lock_puzzle_ex puzzle_ex = {0x00};

  gk_crypto_init();

  err = gk_generate_puzzle(state.range(0), 56392, &puzzle_ex);

  for (auto _ : state) {
    ans = gk_solve_puzzle(&puzzle_ex.puzzle, &err);
    if (err != 0) {
      state.SkipWithError("Failed to solve the puzzle!");
      break;
    }
    if (ans != puzzle_ex.solution) {
      state.SkipWithError("Wrong puzzle solution!");
      break;
    }
  }

  gk_crypto_exit();
}
BENCHMARK(BM_TimeLockPuzzle_Solving)->DenseRange(100, 1000, 100);

BENCHMARK_MAIN();
