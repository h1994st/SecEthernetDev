#include "gtest/gtest.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/err.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/ssl.h>

#include "client.h"
#include "sender.h"
#include "tesla.h"
#include <cstdint>
#include <cstdlib>

class TESLATest : public ::testing::Test {};

TEST_F(TESLATest, TestTESLA) {
  char buff[1024];
  int64 rnonce;
  char sig[1024];
  char msg[] = "Hello Tesla!";
  TESLA_ERR rc = TESLA_OK;
  tesla_sender_session server;
  tesla_auth_tag mtag;
  tesla_client_session client;
  NTP_t tint = NTP_fromMillis(1500);
  EVP_PKEY *pkey = nullptr;
  EVP_PKEY *pubkey = nullptr;
  WOLFSSL_BIO *bio = nullptr;
  hashtable tbl;

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  hashtable_alloc(&tbl, 1000);

  //generate a random nonce
  *(((int32 *) &rnonce) + 1) = (int32) time(nullptr);
  rnonce += clock();
  //just to make this hard predict, xor with something weird from memory
  rnonce = rnonce ^ *(int64 *) sig;

  //set RSA keys
  bio = wolfSSL_BIO_new_file("data/privkey.pem", "rb");
  EXPECT_NE(bio, nullptr);
  pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  wolfSSL_BIO_free(bio);

  bio = wolfSSL_BIO_new_file("data/pubkey.pem", "rb");
  EXPECT_NE(bio, nullptr);
  pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  wolfSSL_BIO_free(bio);

  EXPECT_NE(pkey, nullptr);
  EXPECT_NE(pubkey, nullptr);

  rc = sender_init(&server, &tint, 4, 2500, (void *) rand);
  EXPECT_EQ(rc, TESLA_OK);
  sender_start(&server);
  client_alloc(&client);
  client_set_nonce(&(client), rnonce);
  sender_set_pkey(&server, pkey);
  client_set_pkey(&client, pubkey);

  printf("Writing nonce\n");
  rc = client_write_nonce(&client, sig, 8);
  EXPECT_EQ(rc, TESLA_OK);

  printf("Writing signature tag\n");
  rc = sender_write_sig_tag(&server, sig, sender_sig_tag_size(&server), sig, 8);
  EXPECT_EQ(rc, TESLA_OK);

  sleep(1);
  printf("Reading signature tag\n");
  rc = client_read_sig_tag(&client, sig, sender_sig_tag_size(&server));
  EXPECT_EQ(rc, TESLA_OK);

  printf("Writing authentication tag\n");
  rc = sender_write_auth_tag(&server, &msg, sizeof(msg), buff, 64);
  EXPECT_EQ(rc, TESLA_OK);

  rc = authtag_alloc(&mtag, &(server.ctx));
  EXPECT_EQ(rc, TESLA_OK);

  printf("Reading authentication tag\n");
  rc = client_read_auth_tag(&mtag, &client, buff, 64);
  EXPECT_EQ(rc, TESLA_OK);

  printf("Buffering authentication tag\n");
  rc = client_buffer(&client, &mtag, &msg, sizeof(msg));
  EXPECT_EQ(rc, TESLA_OK);

  //let's mess with Tesla
  printf("Buffering a tampered msg\n");
  msg[0]++;
  rc = client_buffer(&client, &mtag, &msg, sizeof(msg));
  EXPECT_EQ(rc, TESLA_OK);

  printf("Authenticating tags\n");
  rc = client_authenticate(&client, &mtag);
  EXPECT_EQ(rc, TESLA_OK);

  printf("Sleeping again\n");
  sleep(6);

  printf("Writing authentication tag\n");
  rc = sender_write_auth_tag(&server, &msg, sizeof(msg), buff, 64);
  EXPECT_EQ(rc, TESLA_OK);

  printf("Reading authentication tag\n");
  rc = client_read_auth_tag(&mtag, &client, buff, 64);
  EXPECT_EQ(rc, TESLA_OK);

  printf("Buffering authentication tag\n");
  //rc=client_buffer(&client,&mtag,&msg,sizeof(msg));
  EXPECT_EQ(rc, TESLA_OK);

  printf("Authenticating old packets based upon new data\n");
  rc = client_authenticate(&client, &mtag);
  EXPECT_EQ(rc, TESLA_OK);

  printf("Getting an authentic message\n");
  {
    int mlen = 0;
    char *msg = static_cast<char *>(client_get_msg(&client, &mlen));
    if (msg) printf("The message says :\n%s\n", msg);
    else
      printf("There were no authentic messages\n");
    //tesla hands back dynamically allocated data
    free(msg);
  }
  printf("Getting an inauthentic message\n");
  {
    int mlen = 0;
    char *msg = static_cast<char *>(client_get_bad_msg(&client, &mlen));
    if (msg) printf("The message says :\n%s\n", msg);
    else
      printf("There were no inauthentic messages\n");
    free(msg);
  }

  printf("All tests successful!\n");

  return;
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
