#ifndef SECETHERNETDEV_CAN_UDP_RAW_GK_CRYPTO_H
#define SECETHERNETDEV_CAN_UDP_RAW_GK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Gatekeeper crypto */
enum key_type {
  GK_SENDER_KEY,
  GK_RECEIVER_KEY,
};

#define GK_MAC_LEN (32)
#define GK_ETHTYPE_PROOF (0x080A)

int gk_sha256(uint8_t *input, size_t input_size, uint8_t *output);
int gk_hmac_sha256(
    uint8_t *input, size_t input_size, uint8_t *output, enum key_type key);

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
  uint32_t t;

  // Ck
  // NOTE: although the AES key we use is 16 bytes, the encrypted key must align
  //   with the size of `n` because of the modulo operation
  uint8_t Ck[GK_PUZZLE_N_BYTES];

  // Cm
  uint8_t Cm[GK_AES_BLOCK_SIZE];
};

// extend `struct time_lock_puzzle`
struct time_lock_puzzle_ex {
  struct time_lock_puzzle puzzle;
  uint64_t solution;
};

int gk_crypto_init(void);
void gk_crypto_exit(void);

// Inputs:
// - T: solving time in ms
// - S: number of squaring operations per second
// Outputs:
// - Puzzle: n, t, Ck, Cm
// - Answer: a number
int gk_generate_puzzle(
    uint32_t T, uint32_t S, struct time_lock_puzzle_ex *puzzle_ex);

// Input: puzzle
// Output: a number
uint64_t gk_solve_puzzle(struct time_lock_puzzle *puzzle, int *err);

#ifdef __cplusplus
}
#endif

#endif  //SECETHERNETDEV_CAN_UDP_RAW_GK_CRYPTO_H
