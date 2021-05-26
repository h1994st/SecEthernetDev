#ifndef _TESLA_CLIENT_H
#define _TESLA_CLIENT_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/evp.h>

#include "tesla.h"

typedef struct {
  tesla_ctx ctx;
  NTP_t T_off;//offset between client and sender
  hashtable h_unauth;
  llist l_auth;
  llist l_bad;
  int64 nonce;
  void *K_c;
  int32 c;
  EVP_PKEY *pkey;
} tesla_client_session;

/***Functions for dealing with the client session**/
TESLA_ERR client_read_auth_tag(
    tesla_auth_tag *tag, tesla_client_session *sess,
    void *buff, int buflen);
TESLA_ERR client_read_sig_tag(
    tesla_client_session *sess,
    void *buff, int buflen);
TESLA_ERR client_buffer(
    tesla_client_session *sess, tesla_auth_tag *tag,
    void *msg, int32 mlen);
TESLA_ERR client_authenticate(tesla_client_session *, tesla_auth_tag *);
#define client_set_pkey(sess, key) (sess)->pkey = key
TESLA_ERR client_alloc(tesla_client_session *);
TESLA_ERR client_write_nonce(tesla_client_session *, void *buff, int buflen);
void *client_get_msg(tesla_client_session *, int *mlen);
void *client_get_bad_msg(tesla_client_session *, int *mlen);
#define client_set_nonce(sess, n64) (sess)->nonce = n64
#define client_nonce_len(sess) sizeof((sess)->nonce)
int client_key_verify(tesla_client_session *sess, int32 d, void *Kd);
#define client_auth_tag_size(sess) ctx_auth_tag_size(&(sess)->ctx)
#define client_auth_tag_alloc(sess, mtag) authtag_alloc(mtag, &((sess)->ctx))
#define client_new() malloc(sizeof(tesla_client_session))

#endif
