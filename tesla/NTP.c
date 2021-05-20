/* NTP implementation
   handles arithmetic usage and creation
   of NTP timestamps
*/
#include "NTP.h"
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <math.h>
const uint32 FRAC_MAX = 1000000;
#define NTP_TO_DOUBLE(a) ( a->seconds+(double)(a->fraction)/FRAC_MAX )

void NTP_write(void *buf, NTP_t *a) {
  memcpy(buf, &(a->seconds), sizeof(uint32));
  buf += sizeof(uint32);
  memcpy(buf, &(a->fraction), sizeof(uint32));
}

void NTP_read(void *buf, NTP_t *a) {
  memcpy(&(a->seconds), buf, sizeof(uint32));
  buf += sizeof(uint32);
  memcpy(&(a->fraction), buf, sizeof(uint32));
}

void NTP_now(NTP_t *c) {
  struct timeval tv;
  if (gettimeofday(&tv, NULL)) {
    printf("NTP, fatal error");
    exit(-1);
  }
  c->seconds = tv.tv_sec;
  c->fraction = tv.tv_usec;
}

//absolute value of the difference of two times
//|a-b|
NTP_t NTP_dif(NTP_t *a, NTP_t *b) {
  NTP_t ret;
  double time1 = NTP_TO_DOUBLE(a);
  double time2 = NTP_TO_DOUBLE(b);
  time1 = fabs(time1 - time2);
  ret.seconds = (uint32) time1;
  time1 -= ret.seconds;
  ret.fraction = time1 * FRAC_MAX;
  return ret;
}

void NTP_mult(NTP_t *a, uint32 m) {
  double time = NTP_TO_DOUBLE(a);
  time *= m;
  a->seconds = (uint32) time;
  time = time - a->seconds;
  a->fraction = time * FRAC_MAX;
}

NTP_t NTP_add(NTP_t *a, NTP_t *b) {
  int64 frac;
  NTP_t ret;
  frac = (int64) a->fraction + (int64) b->fraction;
  ret.seconds = a->seconds + b->seconds;
  ret.seconds += (frac >> 32);
  ret.fraction = (int32) frac;
  return ret;
}

NTP_t NTP_sub(NTP_t *a, NTP_t *b) {
  NTP_t ret;
  double time1 = NTP_TO_DOUBLE(a);
  double time2 = NTP_TO_DOUBLE(b);
  time1 -= time2;
  ret.seconds = (uint32) time1;
  time1 -= ret.seconds;
  ret.fraction = time1 * FRAC_MAX;
  return ret;
}

uint32 NTP_div(NTP_t *a, NTP_t *b) {
  double time = NTP_TO_DOUBLE(a);
  double time2 = NTP_TO_DOUBLE(b);
  return (uint32) (time / time2);
}

void NTP_divd(NTP_t *a, double b) {
  double time = NTP_TO_DOUBLE(a);
  time /= b;
  a->seconds = (uint32) time;
  time = time - a->seconds;
  a->fraction = time * FRAC_MAX;
}

NTP_t NTP_fromMillis(int32 millis) {
  NTP_t ret;
  ret.seconds = millis;
  ret.fraction = 0;
  NTP_divd(&ret, 1000.0);
  return ret;
}
