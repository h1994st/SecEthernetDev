/* mpicoder.c  -  Coder for the external representation of MPIs
 * Copyright (C) 1998, 1999 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "mpi-internal.h"
#include <linux/bitops.h>
#include <linux/byteorder/generic.h>
#include <linux/count_zeros.h>
#include <linux/scatterlist.h>
#include <linux/string.h>

#define MAX_EXTERN_SCAN_BYTES (16 * 1024 * 1024)
#define MAX_EXTERN_MPI_BITS 16384

/****************
 * Fill the mpi VAL from the hex string in STR.
 */
int mpi_fromstr(MPI val, const char *str) {
  int sign = 0;
  int prepend_zero = 0;
  int i, j, c, c1, c2;
  unsigned int nbits, nbytes, nlimbs;
  mpi_limb_t a;

  if (*str == '-') {
    sign = 1;
    str++;
  }

  /* Skip optional hex prefix.  */
  if (*str == '0' && str[1] == 'x') str += 2;

  nbits = strlen(str);
  if (nbits > MAX_EXTERN_SCAN_BYTES) {
    mpi_clear(val);
    return -EINVAL;
  }
  nbits *= 4;
  if ((nbits % 8)) prepend_zero = 1;

  nbytes = (nbits + 7) / 8;
  nlimbs = (nbytes + BYTES_PER_MPI_LIMB - 1) / BYTES_PER_MPI_LIMB;

  if (val->alloced < nlimbs) mpi_resize(val, nlimbs);

  i = BYTES_PER_MPI_LIMB - (nbytes % BYTES_PER_MPI_LIMB);
  i %= BYTES_PER_MPI_LIMB;
  j = val->nlimbs = nlimbs;
  val->sign = sign;
  for (; j > 0; j--) {
    a = 0;
    for (; i < BYTES_PER_MPI_LIMB; i++) {
      if (prepend_zero) {
        c1 = '0';
        prepend_zero = 0;
      } else
        c1 = *str++;

      if (!c1) {
        mpi_clear(val);
        return -EINVAL;
      }
      c2 = *str++;
      if (!c2) {
        mpi_clear(val);
        return -EINVAL;
      }
      if (c1 >= '0' && c1 <= '9') c = c1 - '0';
      else if (c1 >= 'a' && c1 <= 'f')
        c = c1 - 'a' + 10;
      else if (c1 >= 'A' && c1 <= 'F')
        c = c1 - 'A' + 10;
      else {
        mpi_clear(val);
        return -EINVAL;
      }
      c <<= 4;
      if (c2 >= '0' && c2 <= '9') c |= c2 - '0';
      else if (c2 >= 'a' && c2 <= 'f')
        c |= c2 - 'a' + 10;
      else if (c2 >= 'A' && c2 <= 'F')
        c |= c2 - 'A' + 10;
      else {
        mpi_clear(val);
        return -EINVAL;
      }
      a <<= 8;
      a |= c;
    }
    i = 0;
    val->d[j - 1] = a;
  }

  return 0;
}
//EXPORT_SYMBOL_GPL(mpi_fromstr);

MPI mpi_scanval(const char *string) {
  MPI a;

  a = mpi_alloc(0);
  if (!a) return NULL;

  if (mpi_fromstr(a, string)) {
    mpi_free(a);
    return NULL;
  }
  mpi_normalize_new(a);
  return a;
}
//EXPORT_SYMBOL_GPL(mpi_scanval);

// not used -- by h1994st
//static int count_lzeros(MPI a) {
//  mpi_limb_t alimb;
//  int i, lzeros = 0;
//
//  for (i = a->nlimbs - 1; i >= 0; i--) {
//    alimb = a->d[i];
//    if (alimb == 0) {
//      lzeros += sizeof(mpi_limb_t);
//    } else {
//      lzeros += count_leading_zeros(alimb) / 8;
//      break;
//    }
//  }
//  return lzeros;
//}

/* Perform a two's complement operation on buffer P of size N bytes.  */
static void twocompl(unsigned char *p, unsigned int n) {
  int i;

  for (i = n - 1; i >= 0 && !p[i]; i--)
    ;
  if (i >= 0) {
    if ((p[i] & 0x01)) p[i] = (((p[i] ^ 0xfe) | 0x01) & 0xff);
    else if ((p[i] & 0x02))
      p[i] = (((p[i] ^ 0xfc) | 0x02) & 0xfe);
    else if ((p[i] & 0x04))
      p[i] = (((p[i] ^ 0xf8) | 0x04) & 0xfc);
    else if ((p[i] & 0x08))
      p[i] = (((p[i] ^ 0xf0) | 0x08) & 0xf8);
    else if ((p[i] & 0x10))
      p[i] = (((p[i] ^ 0xe0) | 0x10) & 0xf0);
    else if ((p[i] & 0x20))
      p[i] = (((p[i] ^ 0xc0) | 0x20) & 0xe0);
    else if ((p[i] & 0x40))
      p[i] = (((p[i] ^ 0x80) | 0x40) & 0xc0);
    else
      p[i] = 0x80;

    for (i--; i >= 0; i--) p[i] ^= 0xff;
  }
}

int mpi_print(
    enum gcry_mpi_format format, unsigned char *buffer, size_t buflen,
    size_t *nwritten, MPI a) {
  unsigned int nbits = mpi_get_nbits(a);
  size_t len;
  size_t dummy_nwritten;
  int negative;

  if (!nwritten) nwritten = &dummy_nwritten;

  /* Libgcrypt does no always care to set clear the sign if the value
	 * is 0.  For printing this is a bit of a surprise, in particular
	 * because if some of the formats don't support negative numbers but
	 * should be able to print a zero.  Thus we need this extra test
	 * for a negative number.
	 */
  if (a->sign && mpi_cmp_ui(a, 0)) negative = 1;
  else
    negative = 0;

  len = buflen;
  *nwritten = 0;
  if (format == GCRYMPI_FMT_STD) {
    unsigned char *tmp;
    int extra = 0;
    unsigned int n;

    tmp = mpi_get_buffer(a, &n, NULL);
    if (!tmp) return -EINVAL;

    if (negative) {
      twocompl(tmp, n);
      if (!(*tmp & 0x80)) {
        /* Need to extend the sign.  */
        n++;
        extra = 2;
      }
    } else if (n && (*tmp & 0x80)) {
      /* Positive but the high bit of the returned buffer is set.
			 * Thus we need to print an extra leading 0x00 so that the
			 * output is interpreted as a positive number.
			 */
      n++;
      extra = 1;
    }

    if (buffer && n > len) {
      /* The provided buffer is too short. */
      kfree(tmp);
      return -E2BIG;
    }
    if (buffer) {
      unsigned char *s = buffer;

      if (extra == 1) *s++ = 0;
      else if (extra)
        *s++ = 0xff;
      memcpy(s, tmp, n - !!extra);
    }
    kfree(tmp);
    *nwritten = n;
    return 0;
  } else if (format == GCRYMPI_FMT_USG) {
    unsigned int n = (nbits + 7) / 8;

    /* Note:  We ignore the sign for this format.  */
    /* FIXME: for performance reasons we should put this into
		 * mpi_aprint because we can then use the buffer directly.
		 */

    if (buffer && n > len) return -E2BIG;
    if (buffer) {
      unsigned char *tmp;

      tmp = mpi_get_buffer(a, &n, NULL);
      if (!tmp) return -EINVAL;
      memcpy(buffer, tmp, n);
      kfree(tmp);
    }
    *nwritten = n;
    return 0;
  } else if (format == GCRYMPI_FMT_PGP) {
    unsigned int n = (nbits + 7) / 8;

    /* The PGP format can only handle unsigned integers.  */
    if (negative) return -EINVAL;

    if (buffer && n + 2 > len) return -E2BIG;

    if (buffer) {
      unsigned char *tmp;
      unsigned char *s = buffer;

      s[0] = nbits >> 8;
      s[1] = nbits;

      tmp = mpi_get_buffer(a, &n, NULL);
      if (!tmp) return -EINVAL;
      memcpy(s + 2, tmp, n);
      kfree(tmp);
    }
    *nwritten = n + 2;
    return 0;
  } else if (format == GCRYMPI_FMT_SSH) {
    unsigned char *tmp;
    int extra = 0;
    unsigned int n;

    tmp = mpi_get_buffer(a, &n, NULL);
    if (!tmp) return -EINVAL;

    if (negative) {
      twocompl(tmp, n);
      if (!(*tmp & 0x80)) {
        /* Need to extend the sign.  */
        n++;
        extra = 2;
      }
    } else if (n && (*tmp & 0x80)) {
      n++;
      extra = 1;
    }

    if (buffer && n + 4 > len) {
      kfree(tmp);
      return -E2BIG;
    }

    if (buffer) {
      unsigned char *s = buffer;

      *s++ = n >> 24;
      *s++ = n >> 16;
      *s++ = n >> 8;
      *s++ = n;
      if (extra == 1) *s++ = 0;
      else if (extra)
        *s++ = 0xff;
      memcpy(s, tmp, n - !!extra);
    }
    kfree(tmp);
    *nwritten = 4 + n;
    return 0;
  } else if (format == GCRYMPI_FMT_HEX) {
    unsigned char *tmp;
    int i;
    int extra = 0;
    unsigned int n = 0;

    tmp = mpi_get_buffer(a, &n, NULL);
    if (!tmp) return -EINVAL;
    if (!n || (*tmp & 0x80)) extra = 2;

    if (buffer && 2 * n + extra + negative + 1 > len) {
      kfree(tmp);
      return -E2BIG;
    }
    if (buffer) {
      unsigned char *s = buffer;

      if (negative) *s++ = '-';
      if (extra) {
        *s++ = '0';
        *s++ = '0';
      }

      for (i = 0; i < n; i++) {
        unsigned int c = tmp[i];

        *s++ = (c >> 4) < 10 ? '0' + (c >> 4) : 'A' + (c >> 4) - 10;
        c &= 15;
        *s++ = c < 10 ? '0' + c : 'A' + c - 10;
      }
      *s++ = 0;
      *nwritten = s - buffer;
    } else {
      *nwritten = 2 * n + extra + negative + 1;
    }
    kfree(tmp);
    return 0;
  } else
    return -EINVAL;
}
//EXPORT_SYMBOL_GPL(mpi_print);
