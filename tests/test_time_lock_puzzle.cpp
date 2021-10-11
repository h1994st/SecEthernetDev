#include "gtest/gtest.h"

#include <cstring>

#include "time_lock_puzzle.h"

TEST(TimeLockPuzzleTest, TestEncryptDecrypt) {
  TimeLockPuzzle tlp(4);
  uint8_t msg[16] = {0xde, 0xad, 0xbe, 0xef};

  uint8_t enc_key[512] = {0x00};
  size_t enc_key_len = sizeof(enc_key);

  uint8_t enc_msg[16] = {0x00};
  uint8_t dec_msg[16] = {0x00};

  tlp.encrypt(1, (uint8_t *) msg, sizeof(msg), enc_msg, enc_key, &enc_key_len);

  tlp.decrypt(enc_msg, sizeof(msg), enc_key, enc_key_len, dec_msg);

  ASSERT_EQ(std::memcmp(msg, dec_msg, sizeof(msg)), 0);
}
