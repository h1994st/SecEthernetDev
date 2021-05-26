#include "client.h"
#include "octet_stream.h"
#include <stdlib.h>
#include <string.h>
/*** BJW: 1/20/03
 * Functions for tesla client
 */

TESLA_ERR client_write_nonce(
    tesla_client_session *sess, void *buff, int buflen) {
  octet_stream str = make_octet(buff);
  if (buflen < client_nonce_len(sess))
    return ctx_err(
        &(sess->ctx), "Buffer not long enough for nonce",
        TESLA_ERR_BUFF_SMALL, __FILE__, __LINE__);

  octet_wint64(&str, &(sess->nonce));
  //T_off set to time the nonce was written
  NTP_now(&(sess->T_off));

  return TESLA_OK;
}

//read a message into the authentication tag
TESLA_ERR client_read_auth_tag(
    tesla_auth_tag *tag, tesla_client_session *sess,
    void *buff, int buflen) {
  NTP_t ctime;
  NTP_t ptime;
  TESLA_ERR rc;
  int32 i_past;
  int32 i_curr;
  octet_stream str = make_octet(buff);

  NTP_now(&ctime);
  //the earliest time this packet could have been sent
  ptime = NTP_sub(&ctime, &(sess->T_off));
  octet_rint32(&str, &(tag->i));
  octetrd(&str, tag->Kd, sess->ctx.Key_l);
  rpad(&str);
  octetrd(&str, tag->MAC, sess->ctx.MAC_l);
  rpad(&str);

  //determine if this packet is safe
  rc = ctx_currentInterval(&(sess->ctx), &i_curr, &ctime);
  if (rc == TESLA_OK || (rc == TESLA_ERR_TIME_EXPIRED && i_curr >= sess->ctx.intervals))
    ;
  else
    return rc;
  rc = ctx_currentInterval(&(sess->ctx), &i_past, &ptime);
  if (rc == TESLA_OK || (rc == TESLA_ERR_TIME_EXPIRED && i_past < 0))
    ;
  else
    return rc;

  //see if the interval from the message is within these bounds
  if (tag->i >= i_past && tag->i <= i_curr)
    ;//message is safe
  else
    return ctx_err(
        &(sess->ctx), "Message interval determined to be unsafe",
        TESLA_ERR_TIME_EXPIRED, __FILE__, __LINE__);

  //now, check to see if the key is good
  {
    int32 d = tag->i - sess->ctx.d_int;
    char *kc = malloc(sess->ctx.Key_l);
    if (kc == NULL) return TESLA_ERR_NO_MEMORY;

    memcpy(kc, tag->Kd, sess->ctx.Key_l);
    d = client_key_verify(sess, d, kc);
    free(kc);
    if (d)
      return ctx_err(
          &(sess->ctx), "Key was invalid",
          TESLA_ERR_KEY_INVALID, __FILE__, __LINE__);
  }

  return TESLA_OK;
}

//buffer the message described by the auth tag so it can be later retrieved
//this to be used with normal authentication
TESLA_ERR client_buffer(
    tesla_client_session *sess, tesla_auth_tag *tag,
    void *msg, int32 mlen) {
  TESLA_ERR rc = TESLA_OK;
  tesla_pkt_tag *pkt = pkttag_new();
  llist *plist = NULL;

  if (tag == NULL) return TESLA_ERR_NO_MEMORY;

  //allocate it with the proper info
  rc = pkttag_alloc(pkt, &(sess->ctx), tag->MAC, msg, mlen);
  if (rc != TESLA_OK) return rc;

  //add it to the list of pkts for this interval
  if (!hashtable_lookup(&(sess->h_unauth), tag->i, (void **) &plist)) {
    //make a new list
    plist = llist_new();
    if (!plist) return TESLA_ERR_NO_MEMORY;
    llist_alloc(plist);

    hashtable_insert(&(sess->h_unauth), tag->i, plist);
  }
  llist_add(plist, pkt);

  return TESLA_OK;
}

/* Attempt to authenticate old messages with this tag */
TESLA_ERR client_authenticate(tesla_client_session *sess, tesla_auth_tag *tag) {
  //id of disclosed key
  int32 I_d = tag->i - sess->ctx.d_int;
  void *K = malloc(sess->ctx.Key_l);
  void *Km = malloc(sess->ctx.Key_l);
  void *mac = malloc(sess->ctx.MAC_l);
  TESLA_ERR rc = TESLA_OK;
  tesla_pkt_tag *pkt = NULL;
  llist *plist = NULL;

  if (K == NULL || mac == NULL || Km == NULL) return TESLA_ERR_NO_MEMORY;

  I_d = (I_d < 0) ? 0 : I_d;
  memcpy(K, tag->Kd, sess->ctx.Key_l);

  while (I_d > sess->c) {
    //Km=PRF(K)
    rc = PRF(
        sess->ctx.PRFKey_t, K, sess->ctx.Key_l,
        Km, sess->ctx.Key_l, &(sess->ctx));
    if (rc != TESLA_OK) goto error;

    if (hashtable_lookup(&(sess->h_unauth), I_d, (void **) &plist)) {
      //remove from hashtable, but don't free plist
      hashtable_remove(&(sess->h_unauth), I_d);
      pkt = llist_get(plist);
      while (pkt != NULL) {
        rc = MAC(
            sess->ctx.MAC_t, pkt->msg, pkt->mlen, Km, sess->ctx.Key_l, mac,
            sess->ctx.MAC_l, &(sess->ctx));
        if (rc != TESLA_OK) goto error;

        //pick a list based upon authentication result
        if (memcmp(mac, pkt->MAC, sess->ctx.MAC_l) == 0) {
          //good message
          llist_add(&(sess->l_auth), pkt);
        } else {
          //bad message
          llist_add(&(sess->l_bad), pkt);
        }
        pkt = llist_get(plist);
      }
      free(plist);//now free plist
    }
    //go to a previous key
    I_d--;
    rc = PRF(
        sess->ctx.Key_t, K, sess->ctx.Key_l,
        K, sess->ctx.Key_l, &(sess->ctx));
    if (rc != TESLA_OK) goto error;
  }

  //successful, update the client's highest key
  I_d = tag->i - sess->ctx.d_int;
  I_d = (I_d < 0) ? 0 : I_d;
  if (I_d > sess->c) {
    sess->c = I_d;
    memcpy(sess->K_c, tag->Kd, sess->ctx.Key_l);
  }
  rc = TESLA_OK;

error:
  free(K);
  free(mac);
  free(Km);
  return rc;
}

//NOTE: both these functions return a pointer
//this data was dynamically allocated and must be freed to avoid
//memory leaks
//get an authentic message
//NULL if there are no authentic messages
void *client_get_msg(tesla_client_session *sess, int *mlen) {
  tesla_pkt_tag *pkt = llist_get(&(sess->l_auth));
  void *msg;
  if (pkt == NULL) return NULL;
  msg = pkt->msg;
  *mlen = pkt->mlen;
  pkttag_free(pkt);
  return msg;
}

// get an inauthentic message
// NULL if there are no such messages
void *client_get_bad_msg(tesla_client_session *sess, int *mlen) {
  void *msg;

  tesla_pkt_tag *pkt = llist_get(&(sess->l_bad));

  if (pkt == NULL)
    return NULL;

  msg = pkt->msg;
  *mlen = pkt->mlen;
  pkttag_free(pkt);

  return msg;
}

int client_key_verify(tesla_client_session *sess, int32 d, void *Kd) {
  if (d < 0) d = 0;

  if (d >= sess->c) {
    // a new key, ensure that it is correct via d-c PRF's
    for (; d > sess->c; d--) {
      PRF(
          sess->ctx.Key_t, Kd, sess->ctx.Key_l,
          Kd, sess->ctx.Key_l, &(sess->ctx));
    }

    return memcmp(Kd, sess->K_c, sess->ctx.Key_l);
  } else {
    // old key, very unusual
    printf("Old key disclosed\n");

    return 1;
  }
}

TESLA_ERR client_alloc(tesla_client_session *sess) {
  TESLA_ERR rc = TESLA_OK;
  NTP_t time;
  NTP_now(&time);
  rc = ctx_alloc(&(sess->ctx), &time, 0, 0, 0, 0, 0, 0, 0, 0);

  llist_alloc(&(sess->l_auth));
  llist_alloc(&(sess->l_bad));
  sess->pkey = NULL;
  return TESLA_OK;
}

#define SANITY_ERR(msg) return ctx_err(&(sess->ctx), msg, \
                                       TESLA_ERR_BAD_DATA, __FILE__, __LINE__)

TESLA_ERR client_read_sig_tag(
    tesla_client_session *sess, void *buff, int buflen) {
  octet_stream str = make_octet(buff);
  TESLA_ERR rc = TESLA_OK;
  NTP_t stime;
  NTP_t ctime;
  NTP_now(&ctime);

  rNTP(&str, &(sess->ctx.T_0));
  rNTP(&str, &(sess->ctx.T_int));

  octet_rint16(&str, (int16 *) &(sess->ctx.PRFKey_t));
  octet_rint16(&str, (int16 *) &(sess->ctx.MAC_t));
  octet_rint16(&str, &(sess->ctx.d_int));
  octet_rint16(&str, (int16 *) &(sess->ctx.Key_t));
  octet_rint16(&str, &(sess->ctx.f_hmac));
  octet_rint16(&str, &(sess->ctx.Key_l));
  if (sess->ctx.d_int < 1 || sess->ctx.d_int > MAX_DINT)
    SANITY_ERR("Interval length bad");

  rc = hashtable_alloc(&(sess->h_unauth), sess->ctx.d_int * 4);
  // figure out the mac length
  sess->ctx.MAC_l = MAC_LEN(sess->ctx.MAC_t);
  if (!sess->ctx.MAC_l)
    SANITY_ERR("MAC CTAN invalid");

  // receive K_0
  if (sess->ctx.Key_l <= 0 || sess->ctx.Key_l > MAX_KEY_LEN)
    SANITY_ERR("Key length too large");

  sess->K_c = malloc(sess->ctx.Key_l);
  if (sess->K_c == NULL) return TESLA_ERR_NO_MEMORY;
  octetrd(&str, sess->K_c, sess->ctx.Key_l);
  rpad(&str);
  sess->c = 0;

  octet_rint32(&str, &(sess->ctx.intervals));
  octet_rint16(&str, &(sess->ctx.d_int_n));

  if (sess->ctx.intervals < 1)
    SANITY_ERR("Number of intervals wrong");

  //read when the signature was made, figure out T_off
  rNTP(&str, &stime);
  sess->T_off = NTP_dif(&(sess->T_off), &stime);
  if (NTP_gt(&(sess->T_off), &(sess->ctx.T_int)))
    return ctx_err(
        &(sess->ctx), "T_off too small for packet latency",
        TESLA_ERR_TIME_EXPIRED, __FILE__, __LINE__);

  //signature validation
  {
    int16 sig_type = 0;
    int16 slen = 0;
    char bits = 0;
    //BJW:  presently ignoring the sig type, this needs to be fixed
    octet_rint16(&str, &sig_type);
    octet_rint16(&str, &slen);
    if (slen < 0)
      SANITY_ERR("Bad signature length");
    octet_rbyte(&str, &bits);
    if (sess->pkey && slen) {
      EVP_MD_CTX *ctx = EVP_MD_CTX_new();// -- by h1994st
      const EVP_MD *type = EVP_md5();    // TODO: should avoid MD5 -- by h1994st
      TESLA_ERR rc = TESLA_OK;
      EVP_VerifyInit(ctx, type);
      EVP_VerifyUpdate(ctx, octet_buf(&str), octet_tell(&str));
      EVP_VerifyUpdate(ctx, &(sess->nonce), sizeof(sess->nonce));
      rc = octetEVPread(&str, ctx, sess->pkey, slen);
      EVP_MD_CTX_free(ctx);// -- by h1994st
      /*BJW 2/22/03
       *SSL is giving me massive issues with
       *the public key private key types, commenting this out for now
       *BJW 3/14/03, adding back in */
      switch (rc) {
        case TESLA_ERR_INVALID_SIGNATURE:
          return ctx_err(
              &(sess->ctx), "Signature does not match",
              rc, __FILE__, __LINE__);
        case TESLA_ERR_BAD_SIGNATURE:
          return ctx_err(
              &(sess->ctx), "OpenSSL Error while verifying signature",
              rc, __FILE__, __LINE__);
        case TESLA_OK: break;
        default:
          return ctx_err(
              &(sess->ctx), "Error while verifying signature",
              rc, __FILE__, __LINE__);
      }
    } else if (slen) {
      //the server wrote a signature, and we don't have a key to read it
      return ctx_err(
          &(sess->ctx), "Missing key to verify signature",
          TESLA_ERR_DATA_UNAVAILABLE, __FILE__, __LINE__);
    }
  }
  rpad(&str);

  return TESLA_OK;
}
