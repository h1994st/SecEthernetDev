#ifndef _OCTET_STREAM_H
#define _OCTET_STREAM_H
/**** Bram J. Whillock, 2/23/03
      Octet Stream is a structure and set of functions for
      manipulating aligned streams suitable for network
      communication
*/
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/evp.h>

#include "NTP.h"
#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int32 pos;
  void *cbuff;
} octet_stream;

//constructor, pass in a buffer at which point to begin writing
octet_stream make_octet(void *buf);

/* Octetwrt and read are the most primitive functions
   They write len bytes from s2 to the internal buffer
*/
void octetwrt(octet_stream *str, void const *s2, int len);
void octetrd(octet_stream *, void *, int);

/* rpad and wpad will align the stream for the next read or write
   respectively.  In the case of write, the data will be padded with 0's
   to the aligned boundary */
void rpad(octet_stream *);
void wpad(octet_stream *);

/* octet_buf returns the start of the aligned buffer 
   octet_tell tells the number of bytes written thus far
   octet_skip skips num bytes
*/
#define octet_buf(str) ((str)->cbuff - (str)->pos)
#define octet_tell(str) ((str)->pos)
#define octet_skip(str, num) \
  (str)->pos += num;         \
  (str)->cbuff += num

/* Functions for writing NTP objects to the stream */
void wNTP(octet_stream *str, NTP_t *a);
void rNTP(octet_stream *str, NTP_t *a);

/*
  octet_wint16, octet_wint32,octet_wint64 and the read functions respectively
  read and write either 16, 32, or 64 bit integers to the stream
*/
//Choose appropriate code for htons conversion
#ifdef WORDS_BIGENDIAN
#define octet_wint16(str, num) octetwrt(str, (int16 *) num, sizeof(int16))
#define octet_rint16(str, num) octetrd(str, (int16 *) num, sizeof(int16))
#define octet_wint32(str, num) octetwrt(str, (int32 *) num, sizeof(int32))
#define octet_rint32(str, num) octetrd(str, (int32 *) num, sizeof(int32))
#define octet_wint64(str, k) octetwrt(str, (int64 *) k, sizeof(int64))
#define octet_rint64(str, k) octetrd(str, (int64 *) k, sizeof(int64))
#else
void octet_wint16(octet_stream *, int16 *);
void octet_rint16(octet_stream *, int16 *);
void octet_wint32(octet_stream *, int32 *);
void octet_rint32(octet_stream *, int32 *);
void octet_wint64(octet_stream *, int64 *);
void octet_rint64(octet_stream *, int64 *);
#endif
/* wbyte/rbyte writes or reads a byte to the stream */
#define octet_wbyte(str, c) octetwrt(str, (char *) c, sizeof(char))
#define octet_rbyte(str, c) octetrd(str, (char *) c, sizeof(char))
TESLA_ERR octetEVPread(octet_stream *, EVP_MD_CTX *, EVP_PKEY *, int16);
TESLA_ERR octetEVPSign(
    octet_stream *str, EVP_MD_CTX *ctx, EVP_PKEY *pkey, int16 slen);

#ifdef __cplusplus
}
#endif

#endif


