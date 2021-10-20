#ifndef SECETHERNETDEV_CAN_UDP_RAW_GK_CRYPTO_H
#define SECETHERNETDEV_CAN_UDP_RAW_GK_CRYPTO_H

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

enum key_type {
  GK_SENDER_KEY,
  GK_RECEIVER_KEY,
};

#define GK_MAC_LEN (32)
#define GK_ETHTYPE_PROOF (0x080A)

int gk_sha256(byte *input, word32 input_size, byte *output);
int gk_hmac_sha256(
    byte *input, word32 input_size, byte *output, enum key_type key);

#endif  //SECETHERNETDEV_CAN_UDP_RAW_GK_CRYPTO_H
