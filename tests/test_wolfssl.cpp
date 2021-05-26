#include <cstdint>

#include "gtest/gtest.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bio.h>
#include <wolfssl/ssl.h>

class WolfSSLTest : public ::testing::Test {
  void SetUp() override {}

  void TearDown() override {}
};

TEST_F(WolfSSLTest, TestKeyLoading) {
  auto bio = wolfSSL_BIO_new_file("data/privkey.pem", "rb");
  EXPECT_NE(bio, nullptr);
  auto private_key = wolfSSL_PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
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

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
