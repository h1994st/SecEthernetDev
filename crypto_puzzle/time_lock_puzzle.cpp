#include "time_lock_puzzle.h"

#include <cstdint>
#include <iostream>
#include <string>

TimeLockPuzzle::TimeLockPuzzle(int S) : S(S) {
  int ret;
  BIGNUM *tmp1;
  BIGNUM *tmp2;

  bn_two = BN_new();
  p = BN_new();
  q = BN_new();
  n = BN_new();
  a = BN_new();
  t = BN_new();
  phi_n = BN_new();
  key_bn = BN_new();
  b = BN_new();
  tmp1 = BN_new();
  tmp2 = BN_new();
  if (bn_two == nullptr || p == nullptr || q == nullptr || n == nullptr
      || a == nullptr || t == nullptr || phi_n == nullptr || key_bn == nullptr
      || b == nullptr || tmp1 == nullptr || tmp2 == nullptr) {
    std::cerr << "Failed to create big numbers" << std::endl;
    exit(EXIT_FAILURE);
  }
  BN_init(bn_two);
  BN_init(p);
  BN_init(q);
  BN_init(n);
  BN_init(a);
  BN_init(t);
  BN_init(phi_n);
  BN_init(key_bn);
  BN_init(b);
  BN_init(tmp1);
  BN_init(tmp2);

  // Random number generator
  ret = wc_InitRng(&rng);
  if (ret != 0) {
    std::cerr << "Failed to initialize random number generator" << std::endl;
    exit(EXIT_FAILURE);
  }

  // AES
  ret = wc_AesInit(&aes, nullptr, INVALID_DEVID);
  if (ret != 0) {
    std::cerr << "Failed to initialize AES" << std::endl;
    exit(EXIT_FAILURE);
  }

  // AES key
  ret = wc_RNG_GenerateBlock(&rng, key, sizeof(key));
  if (ret != 0) {
    std::cerr << "Failed to generate AES key" << std::endl;
    exit(EXIT_FAILURE);
  }

  if (BN_bin2bn(key, sizeof(key), key_bn) == nullptr) {
    std::cerr << "Failed to convert AES key to big number" << std::endl;
    exit(EXIT_FAILURE);
  }

  // AES IV
  ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
  if (ret != 0) {
    std::cerr << "Failed to generate AES IV" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Set AES key and IV
  ret = wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION);
  if (ret != 0) {
    std::cerr << "Failed to set AES key and IV" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Initialize big number context
  bn_ctx = BN_CTX_new();
  if (bn_ctx == nullptr) {
    std::cerr << "Failed to create big number context" << std::endl;
    exit(EXIT_FAILURE);
  }
  BN_CTX_init(bn_ctx);

  // Generate two random prime numbers
  ret = BN_generate_prime_ex(p, 512, 0, nullptr, nullptr, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to generate prime number" << std::endl;
    exit(EXIT_FAILURE);
  }

  ret = BN_generate_prime_ex(q, 512, 0, nullptr, nullptr, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to generate prime number" << std::endl;
    exit(EXIT_FAILURE);
  }

  // n = p * q
  ret = BN_mul(n, p, q, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `p * q`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Randomly choose 1 < a < n, but let's choose a = 2
  ret = BN_set_word(a, 2);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to set `a`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // phi_n = (p - 1) * (q - 1)
  // tmp1 = p
  BN_copy(tmp1, p);
  ret = BN_sub_word(tmp1, 1);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `p - 1`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // tmp2 = q
  BN_copy(tmp2, q);
  ret = BN_sub_word(tmp2, 1);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `q - 1`" << std::endl;
    exit(EXIT_FAILURE);
  }

  ret = BN_mul(phi_n, tmp1, tmp2, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `(p - 1) * (q - 1)`" << std::endl;
    exit(EXIT_FAILURE);
  }

  BN_clear_free(tmp1);
  BN_clear_free(tmp2);
}

TimeLockPuzzle::~TimeLockPuzzle() {
  wc_FreeRng(&rng);

  wc_AesFree(&aes);

  BN_CTX_free(bn_ctx);
  bn_ctx = nullptr;

  BN_clear_free(bn_two);
  bn_two = nullptr;
  BN_clear_free(p);
  p = nullptr;
  BN_clear_free(q);
  q = nullptr;
  BN_clear_free(n);
  n = nullptr;
  BN_clear_free(a);
  a = nullptr;
  BN_clear_free(t);
  t = nullptr;
  BN_clear_free(phi_n);
  phi_n = nullptr;
  BN_clear_free(key_bn);
  key_bn = nullptr;
  BN_clear_free(b);
  b = nullptr;
}

void TimeLockPuzzle::encrypt(
    int T, uint8_t *msg, size_t msg_len, uint8_t *enc_msg, uint8_t *enc_key,
    size_t *enc_key_len) {
  int ret;
  BIGNUM *tmp1;
  BIGNUM *tmp2;
  BIGNUM *e;

  tmp1 = BN_new();
  tmp2 = BN_new();
  e = BN_new();
  b = BN_new();
  if (tmp1 == nullptr || tmp2 == nullptr || e == nullptr) {
    std::cerr << "Failed to create big numbers" << std::endl;
    exit(EXIT_FAILURE);
  }
  BN_init(tmp1);
  BN_init(tmp2);
  BN_init(e);

  // Encrypt input message
  ret = wc_AesCbcEncrypt(&aes, enc_msg, msg, msg_len);
  if (ret != 0) {
    std::cerr << "Failed to encrypt input message" << std::endl;
    exit(EXIT_FAILURE);
  }

  // tmp1 = T, tmp2 = S
  BN_set_word(tmp1, T);
  BN_set_word(tmp2, S);

  // t = T * S
  ret = BN_mul(t, tmp1, tmp2, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `T * S`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // e = (2 ^ t) % phi_n
  ret = BN_mod_mul(e, bn_two, t, phi_n, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `(2 ^ t) % phi_n`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // b = (a ^ e) % n
  ret = BN_mod_mul(b, a, e, n, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `(a ^ e) % n`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // enc_key_bn = (key_bn + b) % n
  BIGNUM *enc_key_bn = tmp1;
  ret = BN_mod_add(enc_key_bn, key_bn, b, n, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `(key_bn + b) % n`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Convert big number to bytes
  ret = BN_bn2bin(enc_key_bn, enc_key);
  if (ret == -1) {
    std::cerr << "Failed to convert encrypted key big number to bytes"
              << std::endl;
    exit(EXIT_FAILURE);
  }
  *enc_key_len = ret;

  BN_clear_free(tmp1);
  BN_clear_free(tmp2);
  BN_clear_free(e);
}

void TimeLockPuzzle::decrypt(
    uint8_t *enc_msg, size_t enc_msg_len, uint8_t *enc_key, size_t enc_key_len,
    uint8_t *dec_msg) {
  int ret;

  BIGNUM *tmp1;
  BIGNUM *enc_key_bn;
  BIGNUM *dec_key_bn;

  uint8_t *dec_key;
  size_t dec_key_len;

  tmp1 = BN_new();
  enc_key_bn = BN_new();
  dec_key_bn = BN_new();
  if (tmp1 == nullptr || enc_key_bn == nullptr || dec_key_bn == nullptr) {
    std::cerr << "Failed to create big numbers" << std::endl;
    exit(EXIT_FAILURE);
  }
  BN_init(tmp1);
  BN_init(enc_key_bn);
  BN_init(dec_key_bn);

  // Convert encrypted key to a big number
  if (BN_bin2bn(enc_key, (int) enc_key_len, enc_key_bn) == nullptr) {
    std::cerr << "Failed to convert encrypted key to big number" << std::endl;
    exit(EXIT_FAILURE);
  }

  // init: b = a % n
  ret = BN_mod(b, a, n, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `a % n`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // tmp1 = t
  BN_copy(tmp1, t);
  while (!BN_is_zero(tmp1)) {
    // update b = (b ^ 2) % n
    ret = BN_mod_exp(b, b, bn_two, n, nullptr);
    if (ret != WOLFSSL_SUCCESS) {
      std::cerr << "Failed to calculate `(b ^ 2) % n`" << std::endl;
      exit(EXIT_FAILURE);
    }

    ret = BN_sub_word(tmp1, 1);
    if (ret != WOLFSSL_SUCCESS) {
      std::cerr << "Failed to subtract 1" << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  // dec_key = (enc_key - b) % n
  // tmp1 = enc_key - b
  ret = BN_sub(tmp1, enc_key_bn, b);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `enc_key - b`" << std::endl;
    exit(EXIT_FAILURE);
  }

  // dec_key = tmp1 % n
  ret = BN_mod(dec_key_bn, tmp1, n, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `tmp1 % n`" << std::endl;
    exit(EXIT_FAILURE);
  }

  dec_key_len = BN_num_bytes(dec_key_bn);
  dec_key = (uint8_t *) malloc(dec_key_len * sizeof(uint8_t));
  if (dec_key == nullptr) {
    std::cerr << "Failed to allocate memory" << std::endl;
    exit(EXIT_FAILURE);
  }
  BN_bn2bin(dec_key_bn, dec_key);

  // Set decryption key
  ret = wc_AesSetKey(&aes, dec_key, dec_key_len, iv, AES_DECRYPTION);
  if (ret != 0) {
    std::cerr << "Failed to set AES key and IV" << std::endl;
    exit(EXIT_FAILURE);
  }

  // Decrypt message
  ret = wc_AesCbcDecrypt(&aes, dec_msg, enc_msg, enc_msg_len);
  if (ret != 0) {
    std::cerr << "Failed to decrypt input message" << std::endl;
    exit(EXIT_FAILURE);
  }

  BN_clear_free(tmp1);
  BN_clear_free(enc_key_bn);
  BN_clear_free(dec_key_bn);

  free(dec_key);
}

// benchmark: b = (a ^ (2 ^ t)) mod n
void TimeLockPuzzle::benchmark(int iter) {
  int ret;

  // init: b = a % n
  ret = BN_mod(b, a, n, nullptr);
  if (ret != WOLFSSL_SUCCESS) {
    std::cerr << "Failed to calculate `a % n`" << std::endl;
    exit(EXIT_FAILURE);
  }

  for (int i = 0; i < iter; ++i) {
    // update b = (b ^ 2) % n
    ret = BN_mod_exp(b, b, bn_two, n, nullptr);
    if (ret != WOLFSSL_SUCCESS) {
      std::cerr << "Failed to calculate `(b ^ 2) % n`" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}
