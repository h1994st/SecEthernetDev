
#ifndef TESLA_DEFS_H
#define TESLA_DEFS_H

#include <stdint.h>

typedef int32_t int32;
typedef uint32_t uint32;
typedef int16_t int16;
typedef int64_t int64;
typedef char bool;

#define FALSE 0
#define TRUE 1
#define OCTET_SIZE 4
#define OCTET_LEN(k) (k)+(OCTET_SIZE-((k) % OCTET_SIZE))%OCTET_SIZE

typedef enum {
  TESLA_OK,
  TESLA_ERR_BUFF_SMALL,
  TESLA_ERR_INDEX,
  TESLA_ERR_DATA_UNAVAILABLE,
  TESLA_ERR_CTAN_UNKNOWN,
  TESLA_ERR_TIME_EXPIRED,
  TESLA_ERR_KEY_INVALID,
  TESLA_ERR_NO_MEMORY,
  TESLA_ERR_BAD_SIGNATURE,
  TESLA_ERR_INVALID_SIGNATURE,
  TESLA_ERR_BAD_NONCE,
  TESLA_ERR_BAD_DATA,
  TESLA_ERR_NO_KEYS
} TESLA_ERR;

#endif
