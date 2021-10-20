#include <cstdint>

#include "gtest/gtest.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/ssl.h>

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
