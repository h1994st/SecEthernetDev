#include "gk_crypto.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bn.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/types.h>

#include "wolfssl_ext.h"

/* Gatekeeper crypto */

/* sender */
static byte sender_hmac_key[GK_MAC_LEN] = {0x00};
/* receiver */
static byte receiver_hmac_key[GK_MAC_LEN] = {0x01};
/* authenticator's public key */
static byte auth_pub_key[294] =
    "\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01"
    "\x01\x05\x00\x03\x82\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01"
    "\x00\x9F\x60\xE7\xB8\x2F\x85\x21\x99\x4B\x6F\x9C\x4F\xBA\x25\x54"
    "\xD3\xBE\xD5\x06\x2D\xC3\xD7\xD8\x05\x05\x27\xD5\xF7\xBC\x37\x6C"
    "\x92\xCA\x08\xAA\x5B\x5D\xFF\x23\x29\x17\x83\x92\x56\x6A\x7A\x74"
    "\x20\x2D\x2C\xB0\xF1\x77\x1D\x6A\x17\x85\x73\xF3\xDF\xE6\x21\x4D"
    "\x9F\xE0\x86\xEA\x7D\x5D\x29\x6E\xF6\xA3\x19\xC8\x60\xD7\x9F\xFD"
    "\x25\xD4\x05\xAC\x22\xB2\xBA\xE6\x68\xFC\x59\x34\xC2\xF4\x8D\xEA"
    "\x66\x27\x8E\x4D\x3B\x33\x58\xD1\xD5\x99\x90\x13\xAF\xC1\xC6\x22"
    "\xA7\x33\xB3\x05\xB9\x3E\xA0\x67\x73\xAA\xEC\x75\xD9\x2D\x27\x46"
    "\xF5\x5F\x2D\xF2\x45\xF8\xF4\xE0\x1C\x43\x3E\x57\xDD\x1B\xAB\x13"
    "\xB7\x42\xCD\x5F\x57\x7B\xA5\x5D\x2B\x71\x3D\xC6\xF8\xDE\xD9\x1B"
    "\xFE\xA7\x39\x9C\xAF\xFC\xCE\x4C\x04\x30\xC1\x22\xDA\xB3\xC4\x17"
    "\xAB\x94\xA2\xD4\xC8\x65\x5F\xE5\xE9\x3E\x05\x93\x7D\xA3\x74\x97"
    "\x9C\x47\xDF\x54\x4F\x91\xEE\x7A\x1E\xEB\x21\x34\x8C\x6E\x29\x8C"
    "\x8E\x2C\x54\x95\x5C\xF8\xFD\xAE\x24\x76\x04\x76\x81\xAD\xC5\x10"
    "\x00\xB9\xFF\xCB\xED\xE5\x0C\x06\xD1\xB9\xC4\x79\x58\x65\xC3\x92"
    "\x81\x4C\x41\x1C\x4E\x5E\x47\x9F\x06\x04\x1E\x1C\x1D\xEE\x69\x97"
    "\x51\x02\x03\x01\x00\x01";
uint8_t rsa_hash_input_template[51] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    0x00,  // ..., for hash
};

static int initialized = 0;

static Hmac gk_hmac;
static Sha256 gk_hash;
// Random number generator
static RNG gk_rng;
// AES
static Aes gk_aes;
static byte gk_aes_iv[GK_AES_BLOCK_SIZE] = {0x00};
// RSA
static RsaKey gk_rsa_key;

int gk_crypto_init(void) {
  int ret;
  word32 idx = 0;
  if (initialized != 0) return 0;

  ret = wc_InitRng(&gk_rng);
  if (ret != 0) return -1;

  ret = wc_InitRsaKey(&gk_rsa_key, NULL);
  if (ret != 0) return -1;

  ret = wc_RsaPublicKeyDecode(
      auth_pub_key, &idx, &gk_rsa_key, sizeof(auth_pub_key));
  if (ret != 0) return -1;

  initialized = 1;

  return 0;
}

void gk_crypto_exit(void) {
  if (initialized == 0) return;
  wc_FreeRng(&gk_rng);
  wc_FreeRsaKey(&gk_rsa_key);
  initialized = 0;
}

int gk_rsa2048_verify(
    uint8_t *input, size_t input_size, uint8_t *sig, size_t sig_size) {
  int ret;

  if (gk_crypto_init() != 0) return -1;

  // if wrong hash size
  if (input_size != 32) return -1;

  memcpy(rsa_hash_input_template + 19, input, input_size);

  ret = wc_SignatureVerifyHash(
      WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC, rsa_hash_input_template,
      sizeof(rsa_hash_input_template), sig, sig_size, &gk_rsa_key,
      sizeof(gk_rsa_key));
  if (ret != 0) return ret;

  return 0;
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

int gk_benchmark_puzzle(uint32_t iter) {
  int ret;

  BIGNUM *b;
  BIGNUM *a;
  BIGNUM *n;
  BIGNUM *bn_two;

  b = BN_new();
  a = BN_new();
  n = BN_new();
  bn_two = BN_new();
  if (b == NULL || a == NULL || n == NULL || bn_two == NULL) {
    // Failed to create big numbers
    ret = -1;
    goto failed;
  }
  BN_init(b);
  BN_init(a);
  BN_init(n);
  BN_init(bn_two);

  BN_set_word(a, 2);
  BN_set_word(n, 59833UL * 62549UL);
  BN_set_word(bn_two, 2);

  // init: b = a % n
  ret = BN_mod(b, a, n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `a % n`
    ret = -1;
    goto failed;
  }

  for (int i = 0; i < iter; ++i) {
    // update b = (b ^ 2) % n
    ret = BN_mod_exp(b, b, bn_two, n, NULL);
    if (ret != WOLFSSL_SUCCESS) {
      // Failed to calculate `(b ^ 2) % n`
      ret = -1;
      goto failed;
    }
  }

  ret = 0;

failed:
  BN_clear_free(b);
  BN_clear_free(a);
  BN_clear_free(n);
  BN_clear_free(bn_two);

  return ret;
}

// NOTE: for testing only
static uint8_t p_buf[GK_PUZZLE_PRIME_BITS / 8] =
    "\xF9\xE8\x1E\xB1\x97\xFB\xF3\xFD\x90\x2E\x50\x63\xBE\xA6\xEA\x8D"
    "\x1C\x0B\xB4\x35\x72\x70\xFD\x88\xBC\xD7\xF0\x4A\xAB\x0C\xD8\x7F";
static uint8_t q_buf[GK_PUZZLE_PRIME_BITS / 8] =
    "\xC4\x1D\xA3\x23\x20\xB2\x51\x1B\xC4\x6D\xC1\x6E\xFF\xE6\xDD\x6D"
    "\x41\xEF\x83\x7B\x5A\xAE\x1F\x03\x33\x6A\x46\xCA\x45\x8F\x24\x27";

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
  // NOTE: for now, we use hard-coded prime numbers.
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
  ret = BN_bn2bin(n, puzzle_ex->puzzle.n + GK_PUZZLE_N_BYTES - BN_num_bytes(n));
  if (ret == -1) {
    // Failed to convert `n`
    ret = -1;
    goto failed;
  }

  if (t->fp.used != 1) {
    // `t` is too large
    ret = -1;
    goto failed;
  }
  puzzle_ex->puzzle.t = BN_get_word(t);

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

  // dec_key_bn = (enc_key_bn - b) % n
  ret = BN_mod_sub(dec_key_bn, enc_key_bn, b, n, NULL);
  if (ret != WOLFSSL_SUCCESS) {
    // Failed to calculate `(enc_key_bn - b) % n`
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
