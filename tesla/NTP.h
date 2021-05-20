/*BJW Definition for types and functions for manipulating
  NTP times */

#ifndef TESLA_NTP_H
#define TESLA_NTP_H
#include "defs.h"

typedef struct {
  uint32 seconds;
  uint32 fraction;
} NTP_t;

//size of NTP when written in bytes
#define NTP_SIZE (2 * sizeof(uint32))

void NTP_now(NTP_t *c);//current time
NTP_t NTP_dif(NTP_t *a, NTP_t *b);//a-b
void NTP_mult(NTP_t *a, uint32 m);//a*m
NTP_t NTP_add(NTP_t *a, NTP_t *b);//a+b
NTP_t NTP_sub(NTP_t *a, NTP_t *b);//a-b
uint32 NTP_div(NTP_t *a, NTP_t *b);//a div b(discrete)
void NTP_divd(NTP_t *a, double b);//a / b, non integer
NTP_t NTP_fromMillis(int32 millis);//NTP time from milliseconds
void NTP_write(void *buf, NTP_t *a);
void NTP_read(void *buf, NTP_t *a);
#define NTP_gt(a, b) (((a)->seconds > (b)->seconds) || ((a)->seconds==(b)->seconds && \
                          (a)->fraction > (b)->fraction))

#endif
