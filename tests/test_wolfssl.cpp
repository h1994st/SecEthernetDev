#include <cstdint>

#include "gtest/gtest.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/ssl.h>

/* wolfSSL extension */
static int wolfSSL_BN_mod_sub(
    WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a, const WOLFSSL_BIGNUM *b,
    const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx) {
  (void) ctx;
  WOLFSSL_MSG("wolfSSL_BN_mod_sub");

  if (r == NULL || r->internal == NULL || a == NULL || a->internal == NULL
      || b == NULL || b->internal == NULL || m == NULL || m->internal == NULL) {
    WOLFSSL_MSG("bn NULL error");
    return WOLFSSL_FAILURE;
  }

  if (mp_submod(
          (mp_int *) a->internal, (mp_int *) b->internal,
          (mp_int *) m->internal, (mp_int *) r->internal)
      != MP_OKAY) {
    WOLFSSL_MSG("mp_submod error");
    return WOLFSSL_FAILURE;
  }

  return WOLFSSL_SUCCESS;
}
#define BN_mod_sub wolfSSL_BN_mod_sub

TEST(WolfSSLTest, TestKeyLoading) {
  auto bio = wolfSSL_BIO_new_file("data/privkey.pem", "rb");
  EXPECT_NE(bio, nullptr);
  auto private_key =
      wolfSSL_PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  EXPECT_NE(private_key, nullptr);
  wolfSSL_EVP_PKEY_free(private_key);
  wolfSSL_BIO_free(bio);

  bio = wolfSSL_BIO_new_file("data/pubkey.pem", "rb");
  EXPECT_NE(bio, nullptr);
  auto public_key = wolfSSL_PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  EXPECT_NE(public_key, nullptr);
  wolfSSL_EVP_PKEY_free(public_key);
  wolfSSL_BIO_free(bio);
}

TEST(WolfSSLTest, TestBNModExp) {
  int ret;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *bn_two;
  BIGNUM *phi_n;
  BIGNUM *tmp1;
  BIGNUM *tmp2;

  p = BN_new();
  q = BN_new();
  bn_two = BN_new();
  phi_n = BN_new();
  tmp1 = BN_new();
  tmp2 = BN_new();
  ASSERT_NE(p, nullptr);
  ASSERT_NE(q, nullptr);
  ASSERT_NE(bn_two, nullptr);
  ASSERT_NE(phi_n, nullptr);
  ASSERT_NE(tmp1, nullptr);
  ASSERT_NE(tmp2, nullptr);

  BN_init(p);
  BN_init(q);
  BN_init(bn_two);
  BN_init(phi_n);
  BN_init(tmp1);
  BN_init(tmp2);

  BN_set_word(bn_two, 2);

  // Generate two random prime numbers
//  ret = BN_generate_prime_ex(p, 512, 0, nullptr, nullptr, nullptr);
//  ASSERT_EQ(ret, WOLFSSL_SUCCESS);
//
//  ret = BN_generate_prime_ex(q, 512, 0, nullptr, nullptr, nullptr);
//  ASSERT_EQ(ret, WOLFSSL_SUCCESS);
  // NOTE: for now, just use hard-coded prime numbers
    BN_set_word(p, 59833);
    BN_set_word(q, 62549);

  // phi_n = (p - 1) * (q - 1)
  // tmp1 = p
  BN_copy(tmp1, p);
  ret = BN_sub_word(tmp1, 1);
  ASSERT_EQ(ret, WOLFSSL_SUCCESS);
  // tmp2 = q
  BN_copy(tmp2, q);
  ret = BN_sub_word(tmp2, 1);
  ASSERT_EQ(ret, WOLFSSL_SUCCESS);
  // phi_n = tmp1 * tmp2
  ret = BN_mul(phi_n, tmp1, tmp2, nullptr);
  ASSERT_EQ(ret, WOLFSSL_SUCCESS);

  // tmp2 = 2000
  BN_set_word(tmp2, 2000);
  // tmp1 = (2 ^ tmp2) mod phi_n
  ret = BN_mod_exp(tmp1, bn_two, tmp2, phi_n, nullptr);
  ASSERT_EQ(ret, WOLFSSL_SUCCESS);

  BN_clear_free(p);
  BN_clear_free(q);
  BN_clear_free(bn_two);
  BN_clear_free(phi_n);
  BN_clear_free(tmp1);
  BN_clear_free(tmp2);
}

TEST(WolfSSLTest, TestBNModSub) {
  int ret;
  BIGNUM *a;
  BIGNUM *b;
  BIGNUM *r1;
  BIGNUM *m;

  a = BN_new();
  b = BN_new();
  r1 = BN_new();
  m = BN_new();
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  ASSERT_NE(r1, nullptr);
  ASSERT_NE(m, nullptr);

  BN_init(a);
  BN_init(b);
  BN_init(r1);
  BN_init(m);

  // a > b
  BN_set_word(a, 5);
  BN_set_word(b, 3);
  BN_set_word(m, 10);
  ret = BN_mod_sub(r1, a, b, m, nullptr);
  ASSERT_EQ(ret, WOLFSSL_SUCCESS);

  // a < b
  BN_set_word(a, 1);
  BN_set_word(b, 7);
  BN_set_word(m, 10);
  ret = BN_mod_sub(r1, a, b, m, nullptr);

  BN_clear_free(a);
  BN_clear_free(b);
  BN_clear_free(r1);
  BN_clear_free(m);
}
