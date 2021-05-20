#include "sender.h"
#include "octet_stream.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define TERROR(a) if(a != TESLA_OK){ rc = a; goto error;}
const static int32 ZERO = 0x00000000;

TESLA_ERR sender_alloc(
    tesla_sender_session *sess, NTP_t *T_int, PRF_CTAN key_t,
    int16 key_l, MAC_CTAN mac_t,
    PRF_CTAN mkey_t, int16 d_int, int16 f_hmac,
    int32 intervals, void *pkey) {

  TESLA_ERR rc = TESLA_OK;
  rc = ctx_alloc(
      &(sess->ctx), T_int, key_t, key_l, mac_t, MAC_LEN(mac_t), mkey_t, d_int,
      f_hmac, intervals);
  TERROR(rc);
  if (!MAC_LEN(mac_t))
    return ctx_err(
        &(sess->ctx), "Bad MAC", TESLA_ERR_CTAN_UNKNOWN,
        __FILE__, __LINE__);
  //create the keychain
  rc = keychain_alloc(&(sess->keyring), pkey, key_l, intervals, key_t, 256);
  TERROR(rc);

  sess->K_0 = malloc(key_l);
  if (sess->K_0 == NULL) return TESLA_ERR_NO_MEMORY;

  rc = sender_copy_key(sess, 0, sess->K_0, sess->ctx.Key_l);
  sess->pkey = NULL;

error:
  return rc;
}

void sender_start(tesla_sender_session *sess) {
  //T_0=now()-T_int*2
  NTP_now(&(sess->ctx.T_0));
  sess->ctx.T_0 = NTP_sub(&(sess->ctx.T_0), &(sess->ctx.T_int));
  sess->ctx.T_0 = NTP_sub(&(sess->ctx.T_0), &(sess->ctx.T_int));
}

/*Writes the signature tag to the specified buffer
See the IETF technical draft for details on the meaning of each field
ANY changes to this function must be reflected in 
sender_sig_tag_size(sender.h)
*/
TESLA_ERR sender_write_sig_tag(
    tesla_sender_session *sess, void *buf,
    int buflen, void *nbuff, int nlen) {
  char bits = 0x00;
  octet_stream str = make_octet(nbuff);
  int16 size = 0;
  int64 nonce;
  NTP_t ctime;
  int32 i;

  if (nlen != sizeof(int64))
    return ctx_err(
        &(sess->ctx), "Nonce does not have correct size",
        TESLA_ERR_BUFF_SMALL, __FILE__, __LINE__);
  octet_rint64(&str, &nonce);
  str = make_octet(buf);

  if (buflen < sender_sig_tag_size(sess))
    return ctx_err(
        &(sess->ctx), "Buffer for signature too small",
        TESLA_ERR_BUFF_SMALL, __FILE__, __LINE__);

  wNTP(&str, &(sess->ctx.T_0));
  wNTP(&str, &(sess->ctx.T_int));

  octet_wint16(&str, (int16 *) &(sess->ctx.PRFKey_t));
  octet_wint16(&str, (int16 *) &(sess->ctx.MAC_t));
  octet_wint16(&str, &(sess->ctx.d_int));
  octet_wint16(&str, (int16 *) &(sess->ctx.Key_t));
  octet_wint16(&str, &(sess->ctx.f_hmac));
  octet_wint16(&str, &(sess->ctx.Key_l));

  octetwrt(&str, sess->K_0, sess->ctx.Key_l);
  wpad(&str);
  i = octet_tell(&str);

  octet_wint32(&str, &(sess->ctx.intervals));
  octet_wint16(&str, &(sess->ctx.d_int_n));

  NTP_now(&ctime);
  wNTP(&str, &ctime);

  //construct appropriate bits
  bits |= 1 << 7;//F
  bits |= 1 << 6;//I
  //signature, presently not in use
  //signature type written here:
  octet_wint16(&str, (int16 *) &(ZERO));
  //SSL signature code
  if (sess->pkey) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); // -- by h1994st
    const EVP_MD *type = EVP_md5();
    size = EVP_PKEY_size(sess->pkey) + sizeof(int16);
    //signature length written here:
    octet_wint16(&str, &(size));
    //extra informational bits
    octet_wbyte(&str, &(bits));
    EVP_SignInit(ctx, type);
    EVP_SignUpdate(ctx, octet_buf(&str), octet_tell(&str));
    EVP_SignUpdate(ctx, &nonce, sizeof(int64));
    octetEVPSign(&str, ctx, sess->pkey, EVP_PKEY_size(sess->pkey));
    EVP_MD_CTX_free(ctx); // -- by h1994st
  } else {
    octet_wint16(&str, (int16 *) &ZERO);
    //extra informational bits
    octet_wbyte(&str, &(bits));
  }
  wpad(&str);

  printf(
      "%d %lu\n", octet_tell(&str) - i, OCTET_LEN(
      NTP_SIZE + 3 * sizeof(int16) + sizeof(int32) + sizeof(char)
          + (((sess)->pkey) ? EVP_PKEY_size((sess)->pkey) + sizeof(int16)
                            : 0)));
  assert(octet_tell(&str) == sender_sig_tag_size(sess));
  //done writing the signature tag
  return TESLA_OK;
}

/* Writes the authentication tag for message m, and places it in buffer buf
 */
//convenience macro, this function only
#define CTX_ERROR(str) if(rc!=TESLA_OK){ \
    ctx_err(&(sess->ctx),str, \
        rc,__FILE__,__LINE__); \
    goto error; \
  }
TESLA_ERR sender_write_auth_tag(
    tesla_sender_session *sess, void *m, int mlen,
    void *buf, int buflen) {
  int32 i;
  TESLA_ERR rc;
  void *K = NULL;//mac key
  octet_stream str = make_octet(buf);
  //determine if the buffer is large enough
  if (buflen < sender_auth_tag_size(sess)) {
    rc = TESLA_ERR_BUFF_SMALL;
    CTX_ERROR("Not enough data in write buffer");
  }

  rc = ctx_currentInterval(&(sess->ctx), &i, NULL);
  CTX_ERROR("Failed to get current interval");

  //we have to wait at least one disclosure interval
  if (i == 0) {
    rc = TESLA_ERR_DATA_UNAVAILABLE;
    CTX_ERROR("Cannot disclose during the first interval");
  }

  //copy over the id(BJW this should be made optional);
  octet_wint32(&str, &i);

  //copy the disclosed key to the buffer
  if (i - sess->ctx.d_int < 0) {
    rc = sender_copy_key(sess, 0, str.cbuff, sess->ctx.Key_l);
  } else {
    rc = sender_copy_key(sess, i - sess->ctx.d_int, str.cbuff, sess->ctx.Key_l);
  }
  CTX_ERROR("Failed to get disclosed key");

  //pad the buffer
  octetwrt(&str, NULL, sess->ctx.Key_l);
  wpad(&str);


  //get the MAC key
  K = malloc(sess->ctx.Key_l);
  if (K == NULL) { return TESLA_ERR_NO_MEMORY; }
  rc = sender_copy_key(sess, i, K, sess->ctx.Key_l);
  CTX_ERROR("Failed to get current key");

  //for safety, mac_key = PRF(k)
  rc = PRF(
      sess->ctx.PRFKey_t, K, sess->ctx.Key_l,
      K, sess->ctx.Key_l, &(sess->ctx));
  CTX_ERROR("Failed to PRF key");

  rc = MAC(
      sess->ctx.MAC_t, m, mlen, K, sess->ctx.Key_l, str.cbuff,
      sess->ctx.MAC_l, &(sess->ctx));
  CTX_ERROR("Failed to PRF key");
  //pad it
  octetwrt(&str, NULL, sess->ctx.MAC_l);
  wpad(&str);

  assert(octet_tell(&str) == sender_auth_tag_size(sess));

  rc = TESLA_OK;
error:
  free(K);
  return rc;
}

/*Copies a key to the buffer given a specific key index
  the portion of this which generates the keys when needed
  could be offloaded to a secondary thread.
  A thread should wait in copyKey if the generating thread hasn't
  gotten the key it needs yet
*/
TESLA_ERR sender_copy_key(
    tesla_sender_session *sess, int i, void *buf,
    int buflen) {
  //convenience pointer
  tesla_keychain *keyring = &(sess->keyring);
  TESLA_ERR rc;
  /*BJW: assertions removed: 1/20/03
  assert(buflen == sess->ctx.Key_l);
  assert( i>=0);
  assert( i < sess->ctx.intervals);
  assert( i/keyring->buf_size < keyring->keys_len);
  */
  if (i >= sess->ctx.intervals)
    return ctx_err(
        &(sess->ctx), "Out of keys to allocate",
        TESLA_ERR_NO_KEYS, __FILE__, __LINE__);

  //generate the keys if they don't exist
  if (i / keyring->buf_size != keyring->index) {
    void *gkey = keyring->keys + (i / keyring->buf_size) * sess->ctx.Key_l;
    int32 c = keyring->buf_size - 1;
    //tail case, n might not be divisible by the buffer size 
    //in this case the nth key stands for n mod buf keys.
    if (i / keyring->buf_size == keyring->keys_len - 1)
      c = sess->ctx.intervals % keyring->buf_size - 1;

    //copy over the last key
    memcpy(keyring->keybuff + c * sess->ctx.Key_l, gkey, sess->ctx.Key_l);
    c--;

    //generate all the previous keys
    for (; c >= 0; c--) {
      rc = PRF(
          sess->ctx.Key_t, gkey, sess->ctx.Key_l,
          keyring->keybuff + (c * sess->ctx.Key_l), sess->ctx.Key_l,
          &(sess->ctx));
      if (rc != TESLA_OK)
        return ctx_err(
            &(sess->ctx), "Unable to PRF to previous key", rc,
            __FILE__, __LINE__);
      gkey = keyring->keybuff + (c * sess->ctx.Key_l);
    }
  }

  //copy the required key to the buffer
  memcpy(
      buf, keyring->keybuff + (i % keyring->buf_size) * sess->ctx.Key_l,
      buflen);
  return TESLA_OK;
}
