#include "wolfssl_ext.h"

#include <wolfssl/ssl.h>

int wolfSSL_BN_mod_sub(
    WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a, const WOLFSSL_BIGNUM *b,
    const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx) {
  (void) ctx;
  WOLFSSL_MSG("wolfSSL_BN_mod_sub");

  if (r == NULL || r->internal == NULL || a == NULL || a->internal == NULL
      || b == NULL || b->internal == NULL || m == NULL || m->internal == NULL) {
    WOLFSSL_MSG("bn NULL error");
    return WOLFSSL_FAILURE;
  }

  if (mp_submod(
          (mp_int *) a->internal, (mp_int *) b->internal,
          (mp_int *) m->internal, (mp_int *) r->internal)
      != MP_OKAY) {
    WOLFSSL_MSG("mp_submod error");
    return WOLFSSL_FAILURE;
  }

  return WOLFSSL_SUCCESS;
}
