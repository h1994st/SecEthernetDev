#ifndef _TESLA_SAMPLE_H
#define _TESLA_SAMPLE_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HOSTNAME "localhost"
#define SERVERPORT 2345
#define SERVERUDPOUT 2346
#define CLIENTPORT 8888
#define IP_ADDR_FORMAT(x) (int) (((x) >> 24) & 0xff), (int) (((x) >> 16) & 0xff), \
                          (int) (((x) >> 8) & 0xff), (int) ((x) &0xff)

void printbuf(char *, int);

#ifdef WIN32
void handle_error(void);
#define CHECKNEGPE(exp)                          \
  if ((exp) == -1) {                             \
    printf(" Error %s: %i", __FILE__, __LINE__); \
    handle_error();                              \
  }
#else
#define CHECKNEGPE(exp)                          \
  if ((exp) == -1) {                             \
    printf(" Error %s: %i", __FILE__, __LINE__); \
    exit(-1);                                    \
  }
#endif

#ifdef __cplusplus
}
#endif

#endif