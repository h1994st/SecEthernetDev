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

BENCHMARK_MAIN();
