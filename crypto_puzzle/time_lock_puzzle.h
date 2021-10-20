#ifndef SECETHERNETDEV_TIME_LOCK_PUZZLE_H
#define SECETHERNETDEV_TIME_LOCK_PUZZLE_H

#include <wolfssl/options.h>

#include <wolfssl/openssl/bn.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/chacha.h>

class TimeLockPuzzle {
  static constexpr int key_size = 16;
  static constexpr int iv_size = AES_BLOCK_SIZE;

 private:
  BIGNUM *bn_two;

  // Random number generator
  WC_RNG rng = {};

  // AES key & iv
  Aes aes = {};
  byte key[key_size] = {};
  byte iv[iv_size] = {};

  // Big numbers
  BN_CTX *bn_ctx;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *n;  // public
  BIGNUM *a;  // public
  BIGNUM *t;  // public
  BIGNUM *phi_n;
  BIGNUM *key_bn;
  BIGNUM *b;

  int S;

 public:
  explicit TimeLockPuzzle(int S);

  ~TimeLockPuzzle();

  void encrypt(
      int T, uint8_t *msg, size_t msg_len, uint8_t *enc_msg, uint8_t *enc_key,
      size_t *enc_key_len);

  void decrypt(
      uint8_t *enc_msg, size_t enc_msg_len, uint8_t *enc_key,
      size_t enc_key_len, uint8_t *dec_msg);

  // benchmark: b = (a ^ (2 ^ t)) mod n
  void benchmark(int iter = 1000);
};

#endif  //SECETHERNETDEV_TIME_LOCK_PUZZLE_H
