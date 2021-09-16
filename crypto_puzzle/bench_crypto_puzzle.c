#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <wolfssl/wolfcrypt/sha256.h>

// For SHA256, the size of the hash value is 32 bytes
#define MAX_HASH_LEN 32

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

static Sha256 hash;
static uint8_t output[WC_SHA256_DIGEST_SIZE];

static double time_diff(struct timespec begin, struct timespec end) {
  double begin_sec = (double) (begin.tv_sec + begin.tv_nsec * 1.0e-9);
  double end_sec = (double) (end.tv_sec + end.tv_nsec * 1.0e-9);
  return end_sec - begin_sec;
}

static void print_binary_format(uint8_t data[WC_SHA256_DIGEST_SIZE]) {
  for (int i = 0; i < WC_SHA256_DIGEST_SIZE; ++i) {
    printf(BYTE_TO_BINARY_PATTERN" ", BYTE_TO_BINARY(data[i]));
  }
  printf("\n");
}

uint64_t solve(int k, uint8_t mask[WC_SHA256_DIGEST_SIZE]) {
  int ret;
  uint64_t solution = random() % UINT64_MAX;
  int num_checked_bytes = (k + 8) / 8;

  // time measurements
  struct timespec begin, end;

  // reset
  memset(&hash, 0, sizeof(hash));

  clock_gettime(CLOCK_MONOTONIC, &begin);
  for (ret = 1; ret; ++solution) {
    ret = wc_InitSha256(&hash);
    if (ret != 0) { return ret; }

    ret = wc_Sha256Update(&hash, (uint8_t *) &solution, sizeof(solution));
    if (ret != 0) { return ret; }

    ret = wc_Sha256Final(&hash, output);
    if (ret != 0) { return ret; }

    // check prefix
    ret = 0;
    for (int i = 0; i < num_checked_bytes; ++i) {
      ret |= (output[i] & mask[i]);
      if (ret) {
        // wrong solution
        break;
      }
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &end);
  printf("%.9f s\n", time_diff(begin, end));

//  print_binary_format(mask);
//  print_binary_format(output);

  return solution;
}

int main(int argc, char *argv[]) {
  // hardness level
  int k = 0;
  uint8_t mask[WC_SHA256_DIGEST_SIZE];
  // number of iterations
  int n = 1000;

  srandom(time(NULL));

  int opt;
  while ((opt = getopt(argc, argv, "k:n:")) != -1) {
    switch (opt) {  // NOLINT(hicpp-multiway-paths-covered)
      case 'k': {
        k = (int) strtol(optarg, NULL, 10);
        assert(k >= 0 && k <= MAX_HASH_LEN * 8);
        if (k > 64) {
          fprintf(stderr, "the hardness level is too high!\n");
          exit(EXIT_FAILURE);
        }
        break;
      }
      case 'n': {
        n = (int) strtol(optarg, NULL, 10);
        assert(n >= 0);
        break;
      }
      default: break;
    }
  }

  // generate mask
  memset(mask, 0, WC_SHA256_DIGEST_SIZE);
  for (int i = 0, j = k; i < WC_SHA256_DIGEST_SIZE; ++i, j -= 8) {
    if (j < 8) {
      mask[i] = ~((1 << (8 - j)) - 1);
      break;
    }

    mask[i] = 0xff;
  }

  // benchmark
  printf("Running %d times\n", n);
  for (int i = 0; i < n; ++i) {
    printf("%d: ", i);
    solve(k, mask);
  }

  return EXIT_SUCCESS;
}
