//
// Created by h1994st on 10/20/21.
//

#ifndef SECETHERNETDEV_WOLFSSL_EXT_H
#define SECETHERNETDEV_WOLFSSL_EXT_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/openssl/bn.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* wolfSSL extension */
int wolfSSL_BN_mod_sub(
    WOLFSSL_BIGNUM *r, const WOLFSSL_BIGNUM *a, const WOLFSSL_BIGNUM *b,
    const WOLFSSL_BIGNUM *m, WOLFSSL_BN_CTX *ctx);
#define BN_mod_sub wolfSSL_BN_mod_sub

#ifdef __cplusplus
}
#endif

#endif  //SECETHERNETDEV_WOLFSSL_EXT_H
