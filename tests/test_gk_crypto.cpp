#include "gtest/gtest.h"

#include "gk_crypto.h"

TEST(GkCryptoTest, TestTimeLockPuzzle) {
  int ret;
  uint64_t ans;
  time_lock_puzzle_ex puzzle_ex = {0x00};

  gk_crypto_init();

  ret = gk_generate_puzzle(1000, 100, &puzzle_ex);
  EXPECT_EQ(ret, 0);

  ans = gk_solve_puzzle(&puzzle_ex.puzzle, &ret);
  EXPECT_EQ(ret, 0);

  ASSERT_EQ(ans, puzzle_ex.solution);

  gk_crypto_exit();
}

TEST(GkCryptoTest, TestTimeLockPuzzleGeneration) {
  int ret;
  time_lock_puzzle_ex puzzle_ex = {0x00};

  gk_crypto_init();

  for (uint32_t T = 500; T <= 3000; T += 500) {
    ret = gk_generate_puzzle(T, 16771207, &puzzle_ex);
    EXPECT_EQ(ret, 0);
  }

  gk_crypto_exit();
}
