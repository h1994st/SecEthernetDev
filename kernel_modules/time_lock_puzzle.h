#ifndef SECETHERNETDEV_TIME_LOCK_PUZZLE_H
#define SECETHERNETDEV_TIME_LOCK_PUZZLE_H

#include <crypto/aes.h>
#include <linux/mpi.h>

#include "mpi/mpi.h"

#define ETH_P_MITM_PUZZLE 0x080B
#define ETH_P_MITM_PUZZLE_SOLUTION 0x080C

#define GK_AES_KEY_SIZE (16)
#define GK_AES_BLOCK_SIZE (16)
#define GK_PUZZLE_N_BITS (512)
#define GK_PUZZLE_N_BYTES (GK_PUZZLE_N_BITS / 8)
#define GK_PUZZLE_PRIME_BITS (GK_PUZZLE_N_BITS / 2)

struct time_lock_puzzle {
  // n
  uint8_t n[GK_PUZZLE_N_BYTES];

  // a = 2

  // t = T * S
  uint64_t t;

  // Ck
  // NOTE: although the AES key we use is 16 bytes, the encrypted key must align
  //   with the size of `n` because of the modulo operation
  uint8_t Ck[GK_PUZZLE_N_BYTES];

  // Cm
  uint8_t Cm[GK_AES_BLOCK_SIZE];
};
typedef struct time_lock_puzzle time_lock_puzzle;

struct time_lock_puzzle_ctx {
  // AES key & iv
  struct crypto_sync_skcipher *tfm;
  uint8_t key[AES_KEYSIZE_128];
  uint8_t iv[AES_BLOCK_SIZE];
  uint8_t msg[AES_BLOCK_SIZE];

  // Big numbers
  MPI p;
  MPI q;
  MPI n;
  MPI a;
  MPI t;
  MPI phi_n;
  MPI key_bn;
  MPI b;

  int S;
};
typedef struct time_lock_puzzle_ctx time_lock_puzzle_ctx;

time_lock_puzzle_ctx *time_lock_puzzle_ctx_alloc(void);
void time_lock_puzzle_ctx_free(time_lock_puzzle_ctx *puzzle);

void time_lock_puzzle_encrypt(
    time_lock_puzzle_ctx *puzzle, int T, uint8_t *msg, size_t msg_len,
    uint8_t *enc_msg, uint8_t *enc_key, size_t *enc_key_len);
void time_lock_puzzle_decrypt(
    time_lock_puzzle_ctx *puzzle, uint8_t *enc_msg, size_t enc_msg_len,
    uint8_t *enc_key, size_t enc_key_len, uint8_t *dec_msg);

int time_lock_puzzle_generate(
    time_lock_puzzle_ctx *puzzle, int T, time_lock_puzzle *payload,
    uint64_t *solution);

#endif  //SECETHERNETDEV_TIME_LOCK_PUZZLE_H
