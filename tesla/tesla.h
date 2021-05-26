#ifndef TESLA_H
#define TESLA_H

#include "NTP.h"
#include "defs.h"
#include "hashtable.h"

typedef enum {
  HMAC_MD5,
  HMAC_SHA256,
} PRF_CTAN;

#define DEFAULT_PRF HMAC_SHA256
#define DEFAULT_KEYL 12

typedef enum {
  MAC_MD5_64,
  MAC_MD5_96,
  MAC_MD5_128,
  MAC_SHA256,
} MAC_CTAN;

#define DEFAULT_MAC MAC_SHA256
#define MAX_KEY_LEN 32
#define MAX_DINT 128

/*The tesla context structure contains necessary information
 * For a tesla session, it is common to both sender and receiver
 */
typedef struct {
  NTP_t T_int;      //interval time
  NTP_t T_0;        //start of this session
  PRF_CTAN Key_t;   //PRF function for the keychain
  MAC_CTAN MAC_t;   //MAC to be used
  PRF_CTAN PRFKey_t;//PRF for getting real key
  int16 Key_l;      //length of each key
  int16 MAC_l;      //length of the MAC
  int16 d_int;      //disclosure delay
  int16 f_hmac;     //number of forward HMAC's
  int16 d_int_n;    //length of final delay(intervals)
  int32 intervals;  //number of total intervals
  llist err_stack;
} tesla_ctx;

typedef struct {
  int32 err_len;
  int32 err_line;
  TESLA_ERR err_code;
  char *err_string;
  char *err_file;
} tesla_err;

typedef struct {
  int32 index;
  int32 buf_size;
  int32 keys_len;
  void *keys;
  void *keybuff;
} tesla_keychain;

/* The client side object for representing an authentication
   tag read from a message from the sender */
typedef struct {
  int32 i;  //interval this message is from
  void *Kd; //key disclosed in this message
  void *MAC;//MAC for this message
} tesla_auth_tag;

typedef struct {
  void *msg;
  int32 mlen;
  void *MAC;
} tesla_pkt_tag;

//take key k and derive the previous key from it, placing the new key in buff
//Apply the specified PRF function, given a seed
TESLA_ERR PRF(
    PRF_CTAN type, void *key, int keylen, void *out, int outlen,
    tesla_ctx *ctx);
TESLA_ERR MAC(
    MAC_CTAN type, void *msg, int msglen, void *key, int keylen, void *out,
    int outlen, tesla_ctx *ctx);
int16 MAC_LEN(MAC_CTAN type);

TESLA_ERR ctx_currentInterval(tesla_ctx *ctx, int32 *i, NTP_t *a);
TESLA_ERR ctx_alloc(
    tesla_ctx *ctx, NTP_t *T_int, PRF_CTAN key_t,
    int16 key_l, MAC_CTAN mac_t, int16 Mac_l,
    PRF_CTAN mkey_t, int16 d_int, int16 f_hmac,
    int32 intervals);
TESLA_ERR ctx_err(
    tesla_ctx *ctx, char *msg, TESLA_ERR code, char *file, int line);
void ctx_print_err(tesla_ctx *ctx);
#define ctx_auth_tag_size(ctx) (            \
    OCTET_LEN(sizeof(int32) + (ctx)->Key_l) \
    + OCTET_LEN((ctx)->MAC_l))

#define err_new() (tesla_err *) (malloc(sizeof(tesla_err)))

/***Authentication tag, basic structure for containing the information parsed
    from the authentication tag*/
#define authtag_new() malloc(sizeof(tesla_auth_tag));
TESLA_ERR authtag_alloc(tesla_auth_tag *tag, tesla_ctx *ctx);

TESLA_ERR keychain_alloc(
    tesla_keychain *kring, void *mkey, int keylen,
    int32 keys, PRF_CTAN key_t, int32 bufsize);

#define pkttag_new() (tesla_pkt_tag *) (malloc(sizeof(tesla_pkt_tag)))
#define pkttag_free(ptr) \
  free(ptr->MAC);        \
  free(ptr)
TESLA_ERR pkttag_alloc(
    tesla_pkt_tag *, tesla_ctx *ctx, void *MAC,
    void *msg, int32 mlen);
void printbuf(char *, int);

#endif
