#include "client.h"
#include "sender.h"
#include "tesla.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdlib.h>
#include <unistd.h>

#define TERROR(a)      \
  if (a != TESLA_OK) { \
    rc = a;            \
    goto error;        \
  }

int main(int argc, char **argv) {
  char buff[1024];
  int64 rnonce;
  char sig[1024];
  char msg[] = "Hello Tesla!";
  TESLA_ERR rc = TESLA_OK;
  tesla_sender_session server;
  tesla_auth_tag mtag;
  tesla_client_session client;
  NTP_t tint = NTP_fromMillis(1500);
  EVP_PKEY *pkey = NULL;
  EVP_PKEY *pubkey = NULL;
  FILE *pfile = NULL;
  hashtable tbl;

  if (argc < 3) {
    fprintf(stderr, "Not enough arguments\n");
    exit(EXIT_FAILURE);
  }

  //very important
  ERR_load_crypto_strings();

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  hashtable_alloc(&tbl, 1000);

  //generate a random nonce
  *(((int32 *) &rnonce) + 1) = (int32) time(NULL);
  rnonce += clock();
  //just to make this hard predict, xor with something weird from memory
  rnonce = rnonce ^ *(int64 *) sig;

  X509V3_add_standard_extensions();
  // SSLeay_add_all_algorithms(); // -- deleted by h1994st

  //set RSA keys
  pfile = fopen(argv[1], "rb");
  if (!pfile) {
    // no such file
    perror("fopen failed");
    exit(EXIT_FAILURE);
  }
  pkey = PEM_read_PrivateKey(pfile, NULL, NULL, NULL);
  fclose(pfile);

  pfile = fopen(argv[2], "rb");
  if (!pfile) {
    // no such file
    perror("fopen failed");
    exit(EXIT_FAILURE);
  }
  pubkey = PEM_read_PUBKEY(pfile, NULL, NULL, NULL);
  fclose(pfile);

  if (pkey == NULL || pubkey == NULL) goto error;

  rc = sender_init(&server, &tint, 4, 2500, rand);
  TERROR(rc);
  sender_start(&server);
  client_alloc(&client);
  client_set_nonce(&(client), rnonce);
  sender_set_pkey(&server, pkey);
  client_set_pkey(&client, pubkey);

  printf("Writing nonce\n");
  rc = client_write_nonce(&client, sig, 8);
  TERROR(rc);

  printf("Writing signature tag\n");
  rc = sender_write_sig_tag(&server, sig, sender_sig_tag_size(&server), sig, 8);
  TERROR(rc);

  sleep(1);
  printf("Reading signature tag\n");
  rc = client_read_sig_tag(&client, sig, sender_sig_tag_size(&server));
  TERROR(rc);

  printf("Writing authentication tag\n");
  rc = sender_write_auth_tag(&server, &msg, sizeof(msg), buff, 64);
  TERROR(rc);

  rc = authtag_alloc(&mtag, &(server.ctx));
  TERROR(rc);

  printf("Reading authentication tag\n");
  rc = client_read_auth_tag(&mtag, &client, buff, 64);
  TERROR(rc);

  printf("Buffering authentication tag\n");
  rc = client_buffer(&client, &mtag, &msg, sizeof(msg));
  TERROR(rc);

  //let's mess with Tesla
  printf("Buffering a tampered msg\n");
  msg[0]++;
  rc = client_buffer(&client, &mtag, &msg, sizeof(msg));
  TERROR(rc);

  printf("Authenticating tags\n");
  rc = client_authenticate(&client, &mtag);
  TERROR(rc);

  printf("Sleeping again\n");
  sleep(6);

  printf("Writing authentication tag\n");
  rc = sender_write_auth_tag(&server, &msg, sizeof(msg), buff, 64);
  TERROR(rc);

  printf("Reading authentication tag\n");
  rc = client_read_auth_tag(&mtag, &client, buff, 64);
  TERROR(rc);

  printf("Buffering authentication tag\n");
  //rc=client_buffer(&client,&mtag,&msg,sizeof(msg));
  TERROR(rc);

  printf("Authenticating old packets based upon new data\n");
  rc = client_authenticate(&client, &mtag);
  TERROR(rc);

  printf("Getting an authentic message\n");
  {
    int mlen = 0;
    char *msg = client_get_msg(&client, &mlen);
    if (msg) printf("The message says :\n%s\n", msg);
    else
      printf("There were no authentic messages\n");
    //tesla hands back dynamically allocated data
    free(msg);
  }
  printf("Getting an inauthentic message\n");
  {
    int mlen = 0;
    char *msg = client_get_bad_msg(&client, &mlen);
    if (msg) printf("The message says :\n%s\n", msg);
    else
      printf("There were no inauthentic messages\n");
    free(msg);
  }

  printf("All tests successful!\n");

error:
  ctx_print_err(&(server.ctx));
  ctx_print_err(&(client.ctx));
  printf("Last SSL error,%s\n", ERR_error_string(ERR_get_error(), NULL));
  return -1;
}
