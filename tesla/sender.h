#ifndef _TESLA_SENDER_H
#define _TESLA_SENDER_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/evp.h>

#include "tesla.h"

typedef struct {
  tesla_ctx ctx;
  tesla_keychain keyring;
  void *K_0;
  EVP_PKEY *pkey;
} tesla_sender_session;

//declare a new sender session
#define sender_new() malloc(sizeof(tesla_sender_session))
//Internal function mostly
//copies the key for i over to the specified buffer
TESLA_ERR sender_copy_key(tesla_sender_session *, int i, void *buf, int buflen);
//allocates a sender session with the specified parameters
TESLA_ERR sender_alloc(
    tesla_sender_session *sess, NTP_t *T_int, PRF_CTAN key_t,
    int16 key_l, MAC_CTAN mac_t, PRF_CTAN mkey_t,
    int16 d_int, int16 f_hmac, int32 intervals, void *pkey);
//allocates a sender session with some default parameters
#define sender_init(sess, T_int, d_int, intervals, rand)            \
  sender_alloc(sess, T_int, DEFAULT_PRF, DEFAULT_KEYL, DEFAULT_MAC, \
               DEFAULT_PRF, d_int, 0, intervals, rand)
//Writes an authentication tage for the message M to buffer buf
//buflen must be at least sender_auth_tag_size
TESLA_ERR sender_write_auth_tag(
    tesla_sender_session *sess, void *m,
    int mlen, void *buf, int buflen);
//Writes a signature tag to the buffer b based on nonce
//blen >=sender_sig_tag_size
TESLA_ERR sender_write_sig_tag(
    tesla_sender_session *sess, void *b,
    int blen, void *nonce, int nlen);
//Set the private EVP key for this sender, needed if you want
//the data to be authenticated
#define sender_set_pkey(sess, key) ((sess)->pkey) = key
//returns the size for a signature tag
//this will remain constant for a session so long as parameters do not change
//and the private key does not change
#define sender_sig_tag_size(sess) ( \
    OCTET_LEN(2 * NTP_SIZE + 6 * sizeof(int16) + (sess)->ctx.Key_l) + \
    OCTET_LEN(NTP_SIZE + 3 * sizeof(int16) + sizeof(int32) + sizeof(char) + \
              (((sess)->pkey) ? EVP_PKEY_size((sess)->pkey) + sizeof(int16) : 0)))
//returns the size for an authentication tag
//won't change unless the session parameters change
#define sender_auth_tag_size(sess) ctx_auth_tag_size(&((sess)->ctx))
//Starts the Tesla sender session
void sender_start(tesla_sender_session *sess);

#endif
