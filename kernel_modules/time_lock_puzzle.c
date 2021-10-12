#include "time_lock_puzzle.h"

#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/skcipher.h>

time_lock_puzzle *time_lock_puzzle_alloc(void) {
  int ret;
  time_lock_puzzle *puzzle = NULL;
  MPI tmp1 = NULL;
  MPI tmp2 = NULL;

  // Allocate memory
  puzzle = (time_lock_puzzle *) kzalloc(sizeof(time_lock_puzzle), GFP_KERNEL);
  if (!puzzle) {
    pr_err("cannot allocate memory for time_lock_puzzle\n");
    return NULL;
  }

  // AES
  puzzle->tfm = crypto_alloc_sync_skcipher("cbc(aes)", 0, 0);
  if (IS_ERR(puzzle->tfm)) {
    pr_err("Cannot allocate cbc(aes) handle: %ld\n", PTR_ERR(puzzle->tfm));
    kfree(puzzle);
    return NULL;
  }

  // Generate AES key and IV
//  get_random_bytes(puzzle->key, sizeof(puzzle->key));
//  get_random_bytes(puzzle->iv, sizeof(puzzle->iv));
  // NOTE: for now, use hard-coded key and IV
  memset(puzzle->key, 2, sizeof(puzzle->key));
  memset(puzzle->iv, 3, sizeof(puzzle->iv));

  // Set AES key and IV
  ret = crypto_sync_skcipher_setkey(puzzle->tfm, puzzle->key, sizeof(puzzle->key));
  if (ret < 0) {
    pr_err("Cannot set key: %d\n", ret);
    crypto_free_sync_skcipher(puzzle->tfm);
    kfree(puzzle);
    return NULL;
  }

  // Big numbers
  // TODO: generate two random prime numbers. See wolfSSL's implementation as an
  //  example.
  // NOTE: for now, just hard coded p and q
  puzzle->p = mpi_alloc_set_ui(59833);
  puzzle->q = mpi_alloc_set_ui(62549);
  puzzle->n = mpi_new(0);
  // TODO: should randomly choose 1 < a < n, but let's choose a = 2
  puzzle->a = mpi_alloc_set_ui(2);
  puzzle->t = mpi_new(0);
  puzzle->phi_n = mpi_new(0);
  puzzle->key_bn = mpi_new(0);
  puzzle->b = mpi_new(0);

  // n = p * q
  mpi_mul(puzzle->n, puzzle->p, puzzle->q);

  // phi_n = (p - 1) * (q - 1)
  tmp1 = mpi_alloc(mpi_get_nlimbs(puzzle->p));
  tmp2 = mpi_alloc(mpi_get_nlimbs(puzzle->q));
  // tmp1 = p - 1
  mpi_sub_ui(tmp1, puzzle->p, 1);
  // tmp2 = q - 1
  mpi_sub_ui(tmp2, puzzle->q, 1);
  mpi_mul(puzzle->phi_n, tmp1, tmp2);

  mpi_free(tmp1);
  mpi_free(tmp2);

  return puzzle;
}

void time_lock_puzzle_free(time_lock_puzzle *puzzle) {
  if (puzzle == NULL) return;

  crypto_free_sync_skcipher(puzzle->tfm);

  mpi_free(puzzle->p);
  mpi_free(puzzle->q);
  mpi_free(puzzle->n);
  mpi_free(puzzle->a);
  mpi_free(puzzle->t);
  mpi_free(puzzle->phi_n);
  mpi_free(puzzle->key_bn);
  mpi_free(puzzle->b);
}

void time_lock_puzzle_encrypt(
    time_lock_puzzle *puzzle, int T, uint8_t *msg, size_t msg_len,
    uint8_t *enc_msg, uint8_t *enc_key, size_t *enc_key_len) {
  int ret;
  MPI tmp1 = NULL;
  MPI tmp2 = NULL;
  MPI e = NULL;
  struct scatterlist sg;
  SYNC_SKCIPHER_REQUEST_ON_STACK(req, puzzle->tfm);

  e = mpi_new(0);

  // Encrypt input message
  memcpy(enc_msg, msg, msg_len);
  sg_init_one(&sg, enc_msg, msg_len);

  skcipher_request_set_sync_tfm(req, puzzle->tfm);
  skcipher_request_set_callback(req, 0, NULL, NULL);
  skcipher_request_set_crypt(req, &sg, &sg, msg_len, puzzle->iv);
  ret = crypto_skcipher_encrypt(req);
  if (ret < 0) {
    pr_err("Cannot encrypt input message: %d\n", ret);
    goto out;
  }

  // t = T * S
  // tmp1 = T, tmp2 = S
  tmp1 = mpi_alloc_set_ui(T);
  tmp2 = mpi_alloc_set_ui(puzzle->S);
  mpi_mul(puzzle->t, tmp1, tmp2);

  // e = (2 ^ t) % phi_n
  mpi_powm(e, mpi_const(MPI_C_TWO), puzzle->t, puzzle->phi_n);

  // b = (a ^ e) % n
  mpi_powm(puzzle->b, puzzle->a, e, puzzle->n);

  // enc_key_bn = (key_bn + b) % n
  // Use `tmp1` to store `enc_key_bn`
  mpi_addm(tmp1, puzzle->key_bn, puzzle->b, puzzle->n);

  // Convert big number to bytes
  *enc_key_len = mpi_get_size(tmp1);
  ret = mpi_read_buffer(
      tmp1, enc_key, *enc_key_len, (unsigned int *) enc_key_len, NULL);
  if (ret != 0) {
    pr_err("Cannot convert big number to bytes\n");
    goto out;
  }

out:
  skcipher_request_zero(req);

  mpi_free(tmp1);
  mpi_free(tmp2);
  mpi_free(e);
}

void time_lock_puzzle_decrypt(
    time_lock_puzzle *puzzle, uint8_t *enc_msg, size_t enc_msg_len,
    uint8_t *enc_key, size_t enc_key_len, uint8_t *dec_msg) {
  int ret;
  MPI tmp1 = NULL;
  MPI enc_key_bn = NULL;
  MPI dec_key_bn = NULL;
  MPI bn_two = NULL;

  uint8_t *dec_key = NULL;
  size_t dec_key_len;
  struct scatterlist sg;
  SYNC_SKCIPHER_REQUEST_ON_STACK(req, puzzle->tfm);

  dec_key_bn = mpi_new(0);
  bn_two = mpi_const(MPI_C_TWO);

  // Convert encrypted key to a big number
  enc_key_bn = mpi_read_raw_data(enc_key, enc_key_len);
  if (enc_key_bn == NULL) {
    pr_err("Cannot convert encrypted key to a big number\n");
    goto out;
  }

  // init: b = a % n
  mpi_mod(puzzle->b, puzzle->a, puzzle->n);

  // tmp1 = t
  tmp1 = mpi_copy(puzzle->t);
  // while `tmp1` is not zero
  while (mpi_cmp_ui(tmp1, 0) != 0) {
    mpi_powm(puzzle->b, puzzle->b, bn_two, puzzle->n);
    mpi_sub_ui(tmp1, tmp1, 1);
  }

  // dec_key = (enc_key_bn - b) % n
  // tmp1 = enc_key_bn - b
  mpi_sub(tmp1, enc_key_bn, puzzle->b);
  // dec_key_bn = tmp1 % n
  mpi_mod(dec_key_bn, tmp1, puzzle->n);

  // Convert big number to binary
  dec_key = mpi_get_buffer(dec_key_bn, (unsigned int *) &dec_key_len, NULL);
  if (dec_key != NULL) {
    pr_err("Cannot convert big number to bytes\n");
    goto out;
  }

  // Set decryption key
  ret = crypto_sync_skcipher_setkey(puzzle->tfm, dec_key, dec_key_len);
  if (ret < 0) {
    pr_err("Cannot set decryption key: %d\n", ret);
    goto out;
  }

  // Decrypt message
  memcpy(dec_msg, enc_msg, enc_msg_len);
  sg_init_one(&sg, dec_msg, enc_msg_len);

  skcipher_request_set_sync_tfm(req, puzzle->tfm);
  skcipher_request_set_callback(req, 0, NULL, NULL);
  skcipher_request_set_crypt(req, &sg, &sg, enc_msg_len, puzzle->iv);
  ret = crypto_skcipher_decrypt(req);
  if (ret < 0) {
    pr_err("Cannot encrypt input message: %d\n", ret);
    goto out;
  }

out:
  skcipher_request_zero(req);

  mpi_free(enc_key_bn);
  mpi_free(dec_key_bn);

  kfree(dec_key);
}
