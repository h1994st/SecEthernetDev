#include "gk_crypto.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bn.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/types.h>

/* sender */
static byte sender_hmac_key[GK_MAC_LEN] = {0x00};
/* receiver */
static byte receiver_hmac_key[GK_MAC_LEN] = {0x01};

static int initialized = 0;

static Hmac gk_hmac;
static Sha256 gk_hash;
// Random number generator
static RNG gk_rng;
// AES
static Aes gk_aes;
static byte gk_aes_iv[GK_AES_BLOCK_SIZE] = {0x00};

int gk_crypto_init(void) {
  int ret;
  if (initialized != 0) return 0;

  ret = wc_InitRng(&gk_rng);
  if (ret != 0) return -1;

  initialized = 1;

  return 0;
}

void gk_crypto_exit(void) {
  if (initialized == 0) return;
  wc_FreeRng(&gk_rng);
}

int gk_sha256(uint8_t *input, size_t input_size, uint8_t *output) {
  int ret;
  memset(&gk_hash, 0, sizeof(gk_hash));

  ret = wc_InitSha256(&gk_hash);
  if (ret != 0) { return ret; }

  ret = wc_Sha256Update(&gk_hash, input, input_size);
  if (ret != 0) { return ret; }

  ret = wc_Sha256Final(&gk_hash, output);
  if (ret != 0) { return ret; }

  return 0;
}

int gk_hmac_sha256(
    uint8_t *input, size_t input_size, uint8_t *output, enum key_type key) {
  int ret;
  byte *hmac_key;
  memset(&gk_hmac, 0, sizeof(gk_hmac));

  if (key == GK_SENDER_KEY) {
    hmac_key = sender_hmac_key;
  } else {
    hmac_key = receiver_hmac_key;
  }

  ret = wc_HmacInit(&gk_hmac, NULL, INVALID_DEVID);
  if (ret != 0) { return ret; }

  ret = wc_HmacSetKey(&gk_hmac, WC_SHA256, hmac_key, GK_MAC_LEN);
  if (ret != 0) { return ret; }

  ret = wc_HmacUpdate(&gk_hmac, input, input_size);
  if (ret != 0) { return ret; }

  ret = wc_HmacFinal(&gk_hmac, output);
  if (ret != 0) { return ret; }

  return 0;
}

// Puzzle: n, t, Ck, Cm
// Answer: a number
int gk_generate_puzzle(
    uint32_t T, uint32_t S, struct time_lock_puzzle_ex *puzzle_ex) {
  int ret;
  BIGNUM *bn_two;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *n;  // public
  BIGNUM *a;  // public
  BIGNUM *t;  // public
  BIGNUM *phi_n;
  BIGNUM *key_bn;
  BIGNUM *b;
  BIGNUM *e;

  BIGNUM *tmp1;
  BIGNUM *tmp2;

  // AES key & iv
  byte key[GK_AES_KEY_SIZE] = {};
  //  byte iv[GK_AES_BLOCK_SIZE] = {};
  byte msg[GK_AES_BLOCK_SIZE] = {};

  if (gk_crypto_init() != 0) {
    ret = -1;
    goto out;
  }

  bn_two = BN_new();
  p = BN_new();
  q = BN_new();
  n = BN_new();
  a = BN_new();
  t = BN_new();
  phi_n = BN_new();
  key_bn = BN_new();
  b = BN_new();
  e = BN_new();
  tmp1 = BN_new();
  tmp2 = BN_new();
  if (bn_two == NULL || p == NULL || q == NULL || n == NULL || a == NULL
      || t == NULL || phi_n == NULL || key_bn == NULL || b == NULL || e == NULL
      || tmp1 == NULL || tmp2 == NULL) {
    // Failed to create big numbers
    ret = -1;
    goto failed;
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
  BN_init(e);
  BN_init(tmp1);
  BN_init(tmp2);

  // Set bn_two = 2
  BN_set_word(bn_two, 2);

  // AES
  ret = wc_AesInit(&gk_aes, NULL, INVALID_DEVID);
  if (ret != 0) {
    // Failed to initialize AES
    ret = -1;
    goto failed;
  }

  // AES key
  ret = wc_RNG_GenerateBlock(&gk_rng, key, sizeof(key));
  if (ret != 0) {
    // Failed to generate AES key
    ret = -1;
    goto failed;
  }

  if (BN_bin2bn(key, sizeof(key), key_bn) == NULL) {
    // Failed to convert AES key to big number
    ret = -1;
    goto failed;
  }

  // AES IV
  //  ret = wc_RNG_GenerateBlock(&gk_rng, iv, sizeof(iv));
  //  if (ret != 0) {
  //    // Failed to generate AES IV
  //    ret = -1;
  //    goto failed;
  //  }

  // Set AES key and IV
  ret = wc_AesSetKey(&gk_aes, key, sizeof(key), gk_aes_iv, AES_ENCRYPTION);
  if (ret != 0) {
    // Failed to set AES key and IV
    ret = -1;
    goto failed;
  }

  // Generate the solution number
  ret = wc_RNG_GenerateBlock(
      &gk_rng, (byte *) &puzzle_ex->solution, sizeof(puzzle_ex->solution));
  if (ret != 0) {
    // Failed to generate the solution number
    ret = -1;
    goto failed;
  }
  memset(msg, 0, sizeof(msg));
  memcpy(msg, (uint8_t *) &puzzle_ex->solution, sizeof(puzzle_ex->solution));

  // Generate two random prime numbers
  ret = BN_generate_prime_ex(p, GK_PUZZLE_PRIME_BITS, 0, NULL, NULL, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to generate prime number
    ret = -1;
    goto failed;
  }

  ret = BN_generate_prime_ex(q, GK_PUZZLE_PRIME_BITS, 0, NULL, NULL, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to generate prime number
    ret = -1;
    goto failed;
  }
  // NOTE: for now, we use hard-coded prime numbers. After the pull request
  // (#4481) is merged into wolfSSL, we can use randomly-generated prime numbers
  //  BN_set_word(p, 59833);
  //  BN_set_word(q, 62549);

  // n = p * q
  ret = BN_mul(n, p, q, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `p * q`
    ret = -1;
    goto failed;
  }

  // Randomly choose 1 < a < n, but let's choose a = 2
  ret = BN_set_word(a, 2);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to set `a`
    ret = -1;
    goto failed;
  }

  // phi_n = (p - 1) * (q - 1)
  // tmp1 = p
  BN_copy(tmp1, p);
  ret = BN_sub_word(tmp1, 1);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `p - 1`
    ret = -1;
    goto failed;
  }

  // tmp2 = q
  BN_copy(tmp2, q);
  ret = BN_sub_word(tmp2, 1);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `q - 1`
    ret = -1;
    goto failed;
  }

  ret = BN_mul(phi_n, tmp1, tmp2, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `(p - 1) * (q - 1)`
    ret = -1;
    goto failed;
  }

  // Encrypt input message
  ret = wc_AesCbcEncrypt(&gk_aes, puzzle_ex->puzzle.Cm, msg, sizeof(msg));
  if (ret != 0) {
    // Failed to encrypt input message
    ret = -1;
    goto failed;
  }

  // tmp1 = T, tmp2 = S
  BN_set_word(tmp1, T);  // ms
  BN_set_word(tmp2, S);

  // t = T * S / 1000
  ret = BN_mul(t, tmp1, tmp2, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `T * S`
    ret = -1;
    goto failed;
  }
  BN_set_word(tmp2, 1000);
  ret = BN_div(t, tmp1, t, tmp2, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `T * S / 1000`
    ret = -1;
    goto failed;
  }

  // e = (2 ^ t) % phi_n
  // TODO: !!! the following line is actually a wrong fix. Without the following
  //     line, the error comes from "wolfcrypt/src/tfm.c:Line 3308". That is,
  //     the modulus cannot be even. To address this issue, one may refer other
  //     big number library, like GNU MP.
  if (BN_is_odd(phi_n) != WOLFSSL_SUCCESS) BN_sub_word(phi_n, 1);
  ret = BN_mod_exp(e, bn_two, t, phi_n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `(2 ^ t) % phi_n`
    ret = -1;
    goto failed;
  }

  // b = (a ^ e) % n
  ret = BN_mod_exp(b, a, e, n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `(a ^ e) % n`
    ret = -1;
    goto failed;
  }

  // enc_key_bn = (key_bn + b) % n
  BIGNUM *enc_key_bn = tmp1;
  ret = BN_mod_add(enc_key_bn, key_bn, b, n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `(key_bn + b) % n`
    ret = -1;
    goto failed;
  }

  // Convert big number to bytes
  ret = BN_bn2bin(n, puzzle_ex->puzzle.n);
  if (ret == -1) {
    // Failed to convert `n`
    ret = -1;
    goto failed;
  }

  ret = BN_bn2bin(t, (uint8_t *) &puzzle_ex->puzzle.t);
  if (ret == -1) {
    // Failed to convert `t`
    ret = -1;
    goto failed;
  }

  ret = BN_bn2bin(enc_key_bn, puzzle_ex->puzzle.Ck);
  if (ret == -1) {
    // Failed to convert encrypted key
    ret = -1;
    goto failed;
  }

  ret = 0;

failed:
  BN_clear_free(bn_two);
  BN_clear_free(p);
  BN_clear_free(q);
  BN_clear_free(n);
  BN_clear_free(a);
  BN_clear_free(t);
  BN_clear_free(phi_n);
  BN_clear_free(key_bn);
  BN_clear_free(b);
  BN_clear_free(e);
  BN_clear_free(tmp1);
  BN_clear_free(tmp2);

  wc_AesFree(&gk_aes);

out:
  return ret;
}

// Input: puzzle
// Output: a number
uint64_t gk_solve_puzzle(struct time_lock_puzzle *puzzle, int *err) {
  int ret;
  uint64_t ans = 0;

  BIGNUM *b;
  BIGNUM *a;
  BIGNUM *n;
  BIGNUM *t;
  BIGNUM *bn_two;
  BIGNUM *tmp1;
  BIGNUM *enc_key_bn;
  BIGNUM *dec_key_bn;

  uint8_t *dec_key = NULL;
  size_t dec_key_len;

  uint8_t dec_msg[GK_AES_BLOCK_SIZE] = {};

  b = BN_new();
  a = BN_new();
  n = BN_new();
  t = BN_new();
  bn_two = BN_new();
  tmp1 = BN_new();
  enc_key_bn = BN_new();
  dec_key_bn = BN_new();
  if (b == NULL || a == NULL || n == NULL || t == NULL || bn_two == NULL
      || tmp1 == NULL || enc_key_bn == NULL || dec_key_bn == NULL) {
    // Failed to create big numbers
    *err = -1;
    goto failed;
  }
  BN_init(b);
  BN_init(a);
  BN_init(n);
  BN_init(t);
  BN_init(bn_two);
  BN_init(tmp1);
  BN_init(enc_key_bn);
  BN_init(dec_key_bn);

  BN_set_word(a, 2);
  BN_set_word(bn_two, 2);
  BN_set_word(t, puzzle->t);

  // Convert `n` to a big number
  if (BN_bin2bn(puzzle->n, sizeof(puzzle->n), n) == NULL) {
    // Failed to convert encrypted key to big number
    *err = -1;
    goto failed;
  }

  // Convert encrypted key to a big number
  if (BN_bin2bn(puzzle->Ck, sizeof(puzzle->Ck), enc_key_bn) == NULL) {
    // Failed to convert encrypted key to big number
    *err = -1;
    goto failed;
  }

  // init: b = a % n
  ret = BN_mod(b, a, n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `a % n`
    *err = -1;
    goto failed;
  }

  // tmp1 = t
  BN_copy(tmp1, t);
  while (!BN_is_zero(tmp1)) {
    // update b = (b ^ 2) % n
    ret = BN_mod_exp(b, b, bn_two, n, NULL);
    if (ret != WOLFSSL_SUCCESS) {
      // Failed to calculate `(b ^ 2) % n`
      *err = -1;
      goto failed;
    }

    ret = BN_sub_word(tmp1, 1);
    if (ret != WOLFSSL_SUCCESS) {
      // Failed to subtract 1
      *err = -1;
      goto failed;
    }
  }

  // TODO: better combine `BN_sub` and `BN_mod` together!! Otherwise, the
  //  results seem wrong
  // dec_key = (enc_key_bn - b) % n
  // tmp1 = enc_key_bn - b
  ret = BN_sub(tmp1, enc_key_bn, b);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `enc_key - b`
    *err = -1;
    goto failed;
  }

  // dec_key_bn = tmp1 % n
  ret = BN_mod(dec_key_bn, tmp1, n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `tmp1 % n`
    *err = -1;
    goto failed;
  }

  // Convert big number to binary
  dec_key_len = BN_num_bytes(dec_key_bn);
  dec_key = (uint8_t *) malloc(dec_key_len * sizeof(uint8_t));
  if (dec_key == NULL) {
    // Failed to allocate memory
    *err = -1;
    goto failed;
  }
  BN_bn2bin(dec_key_bn, dec_key);

  // Set decryption key
  ret = wc_AesSetKey(&gk_aes, dec_key, dec_key_len, gk_aes_iv, AES_DECRYPTION);
  if (ret != 0) {
    // Failed to set AES key and IV
    *err = -1;
    goto failed;
  }

  // Decrypt message
  ret = wc_AesCbcDecrypt(&gk_aes, dec_msg, puzzle->Cm, sizeof(puzzle->Cm));
  if (ret != 0) {
    // Failed to decrypt input message
    *err = -1;
    goto failed;
  }

  ans = *((uint64_t *) dec_msg);

  *err = 0;

failed:
  BN_clear_free(b);
  BN_clear_free(a);
  BN_clear_free(n);
  BN_clear_free(t);
  BN_clear_free(bn_two);
  BN_clear_free(tmp1);
  BN_clear_free(enc_key_bn);
  BN_clear_free(dec_key_bn);

  free(dec_key);

  return ans;
}
