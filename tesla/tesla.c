//#include "merkle/merkle_tree.h"
//#include "algorithms/algorithms.h"
#include <stdlib.h>
#include <string.h>
#include "tesla.h"
#include <openssl/evp.h>
#include <assert.h>
#include <openssl/hmac.h>

#define TERROR(a) if(a != TESLA_OK){ rc = a; goto error;}

const int32 ZERO = 0x00000000;

void printbuf(char *s, int slen) {
  int i;
  for (i = 0; i < slen; i++) {
    printf("%.2x", s[i]);
  }
  printf("\n");
}

//allocates the necessary buffers in the tag specified given a particular context
TESLA_ERR authtag_alloc(tesla_auth_tag *tag, tesla_ctx *ctx) {
  tag->Kd = malloc(ctx->Key_l);
  tag->MAC = malloc(ctx->MAC_l);

  if (tag->Kd == NULL || tag->MAC == NULL) return TESLA_ERR_NO_MEMORY;

  return TESLA_OK;
}

TESLA_ERR keychain_alloc(
    tesla_keychain *kring, void *mkey, int keylen, int32 keys, PRF_CTAN key_t,
    int32 bufsize) {
  void *ckey;
  void *ikey;
  int32 k;
  TESLA_ERR rc;
  assert(keys > 0 && bufsize > 0 && keylen > 0 && keys >= bufsize);

  kring->index = -1; //first buffer will be filled on first request to copyKey
  kring->keys_len = keys / bufsize + 1;
  kring->buf_size = bufsize;

  kring->keys = malloc(keylen * kring->keys_len);
  kring->keybuff = malloc(keylen * bufsize);
  ckey = malloc(keylen);
  if (kring->keys == NULL || kring->keybuff == NULL || ckey == NULL)
    return TESLA_ERR_NO_MEMORY;

  ikey = kring->keys + keylen * (kring->keys_len - 1);
  k = keys - 1;
  memcpy(ikey, mkey, keylen);
  memcpy(ckey, mkey, keylen);

  for (; k / bufsize > 0; k--) { //while we're not in the first buffer
    rc = PRF(key_t, ckey, keylen, ckey, keylen, NULL);
    TERROR(rc);

    if (k % bufsize == 0) {
      ikey -= keylen;
      memcpy(ikey, ckey, keylen);
    }
  }

  return TESLA_OK;

error:
  return rc;
}

TESLA_ERR ctx_alloc(
    tesla_ctx *ctx, NTP_t *T_int, PRF_CTAN key_t,
    int16 key_l, MAC_CTAN mac_t, int16 Mac_l, PRF_CTAN mkey_t,
    int16 d_int, int16 f_hmac, int32 intervals) {
  ctx->T_int = *T_int;
  ctx->Key_t = key_t;
  ctx->Key_l = key_l;
  ctx->MAC_t = mac_t;
  ctx->MAC_l = Mac_l;
  ctx->PRFKey_t = mkey_t;
  ctx->d_int = d_int;
  ctx->f_hmac = f_hmac;
  ctx->intervals = intervals;
  llist_alloc(&(ctx->err_stack));
  return TESLA_OK;
}

//currentInterval returns a time expired error if the interval
//determined is invalid for this context
//the interval is still returned in i
TESLA_ERR ctx_currentInterval(tesla_ctx *ctx, int32 *i, NTP_t *atime) {
  NTP_t ctime;
  NTP_t dtime;

  if (atime == NULL)
    NTP_now(&ctime);
  else
    ctime = *atime;
  dtime = NTP_dif(&ctime, &(ctx->T_0));
  *i = NTP_div(&dtime, &(ctx->T_int));
  //the interval could be incorrect, check to see
  //that it is valid for this context
  if (*i < 0 || *i >= ctx->intervals) {
    ctx_err(
        ctx, "Interval determined invalid", TESLA_ERR_TIME_EXPIRED,
        __FILE__, __LINE__);
    return TESLA_ERR_TIME_EXPIRED;
  }
  return TESLA_OK;
}

//in future this should probably be written as some sort of
//queue so that multiple errors can be generated and traced
TESLA_ERR ctx_err(
    tesla_ctx *ctx, char *msg, TESLA_ERR code, char *filename, int line) {
  tesla_err *err = err_new();
  //it's possible we're in memory hell, if err_new fails, we want a diagnostic
  //message and the tesla err returned
  if (ctx == NULL || err == NULL) goto error;

  err->err_len = strlen(msg);
  err->err_string = malloc(err->err_len + 1);
  if (err->err_string == NULL) goto error;

  strncpy(err->err_string, msg, err->err_len + 1);
  err->err_line = line;
  err->err_code = code;
  err->err_file = filename;
  if (llist_add(&(ctx->err_stack), err) != TESLA_OK)
    goto error;

  return code;
error:
  printf(
      "TESLA ERROR %s : %i\n\t%s\nCODE:%i", filename, line,
      msg, code);
  return code;
}

//display a useful error message( a bit cryptic at the moment
void ctx_print_err(tesla_ctx *ctx) {
  tesla_err *cerr = (tesla_err *) llist_get(&(ctx->err_stack));
  if (cerr != NULL) {
    printf("Tesla trace:\n");
    while (cerr != NULL) {
      printf(
          "TESLA ERROR %s : %i\n\t%s\nCODE:%i", cerr->err_file, cerr->err_line,
          cerr->err_string, cerr->err_code);
      free(cerr);
      cerr = llist_get(&(ctx->err_stack));
    }
  } else {
    printf("No tesla errors\n");
  }
}

TESLA_ERR PRF(
    PRF_CTAN type, void *key, int keylen, void *out, int outlen,
    tesla_ctx *ctx) {
  char dummy[32];
  EVP_MD *md;
  int len;
  if (sizeof(dummy) < outlen)
    return ctx_err(
        ctx, "Tesla cannot provide PRF of that size",
        TESLA_ERR_DATA_UNAVAILABLE, __FILE__, __LINE__);

  switch (type) {
    case HMAC_MD5:
      //EVP_md5 returns a constant structure, no need to free it
      md = EVP_md5();

      // Check that MD returns enough bytes for keylength

      if (EVP_MD_size(md) < outlen)
        return ctx_err(
            ctx, "MD5 digest cannot provide enough data",
            TESLA_ERR_DATA_UNAVAILABLE, __FILE__, __LINE__);

      assert(sizeof(dummy) > EVP_MD_size(md));

      HMAC(md, key, keylen, (void *) &ZERO, sizeof(int), dummy, &len);
      if (len < outlen)
        return ctx_err(
            ctx, "MD5 digest did not provide enough data",
            TESLA_ERR_DATA_UNAVAILABLE, __FILE__, __LINE__);

      memcpy(out, dummy, outlen);
      break;
    default:
      return ctx_err(
          ctx, "Unknown PRF CTAN",
          TESLA_ERR_CTAN_UNKNOWN, __FILE__, __LINE__);
  }
  return TESLA_OK;
}

/*Figures out the mac length based upon the mac type
  0 if the type is invalid */
inline int16 MAC_LEN(MAC_CTAN type) {
  switch (type) {
    case MAC_MD5_64: return 8;
    case MAC_MD5_96: return 12;
    case MAC_MD5_128: return 16;
    default: return 0;
  }
}

/* creates a MAC based on the key passed in for message msg.  The mac is placed in
   out an error is returned if there is not enough data to fill out based
   on the MAC type chosen */
TESLA_ERR MAC(
    MAC_CTAN type, void *msg, int mlen, void *key, int keylen, void *out,
    int outlen, tesla_ctx *ctx) {
  EVP_MD *md;
  int len;
  char *mac;
  switch (type) {
    case MAC_MD5_64:
    case MAC_MD5_96:
    case MAC_MD5_128:
      //EVP_md5 returns a constant structure, no need to free it
      md = EVP_md5();

      // Check that MD returns enough bytes for keylength
      if (EVP_MD_size(md) < outlen)
        return ctx_err(
            ctx, "MD5 does not provide enough data for MAC",
            TESLA_ERR_DATA_UNAVAILABLE, __FILE__, __LINE__);

      //WARNING: mac is a static buffer within openssl
      mac = HMAC(md, key, keylen, msg, mlen, NULL, &len);
      if (len < outlen)
        return ctx_err(
            ctx, "MD5 did not provide enough data for MAC",
            TESLA_ERR_DATA_UNAVAILABLE, __FILE__, __LINE__);

      memcpy(out, mac, outlen);
      break;
    default:
      return ctx_err(
          ctx, "Unknown MAC CTAN",
          TESLA_ERR_CTAN_UNKNOWN, __FILE__, __LINE__);
  }
  return TESLA_OK;
}

//authenticate a packet tag, for use in the hashtable
TESLA_ERR pkttag_alloc(
    tesla_pkt_tag *tag, tesla_ctx *ctx, void *MAC, void *msg, int32 mlen) {
  tag->mlen = mlen;
  tag->MAC = malloc(ctx->MAC_l);
  tag->msg = malloc(mlen);
  if (tag->MAC == NULL || tag->msg == NULL) return TESLA_ERR_NO_MEMORY;

  memcpy(tag->MAC, MAC, ctx->MAC_l);
  memcpy(tag->msg, msg, mlen);
  return TESLA_OK;
}
