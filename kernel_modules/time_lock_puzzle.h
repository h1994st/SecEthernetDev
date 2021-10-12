#ifndef SECETHERNETDEV_TIME_LOCK_PUZZLE_H
#define SECETHERNETDEV_TIME_LOCK_PUZZLE_H

#include <crypto/aes.h>
#include <linux/mpi.h>

#include "mpi/mpi.h"

struct time_lock_puzzle {
  // AES key & iv
  struct crypto_sync_skcipher *tfm;
  uint8_t key[AES_KEYSIZE_128];
  uint8_t iv[AES_BLOCK_SIZE];

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

typedef struct time_lock_puzzle time_lock_puzzle;

time_lock_puzzle *time_lock_puzzle_alloc(void);
void time_lock_puzzle_free(time_lock_puzzle *puzzle);

void time_lock_puzzle_encrypt(
    time_lock_puzzle *puzzle, int T, uint8_t *msg, size_t msg_len,
    uint8_t *enc_msg, uint8_t *enc_key, size_t *enc_key_len);
void time_lock_puzzle_decrypt(
    time_lock_puzzle *puzzle, uint8_t *enc_msg, size_t enc_msg_len,
    uint8_t *enc_key, size_t enc_key_len, uint8_t *dec_msg);

#endif  //SECETHERNETDEV_TIME_LOCK_PUZZLE_H
