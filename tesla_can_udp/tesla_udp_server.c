// Server side implementation of UDP client-server model
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include <tesla.h>
#include <client.h>
#include "common.h"

int sockfd = -1;

// TESLA
tesla_client_session receiver;
TESLA_ERR rc = TESLA_OK;
EVP_PKEY *pubkey = NULL;
WOLFSSL_BIO *bio = NULL;
int64_t rnonce;
char *data = NULL;
int peerfd = -1;

void signal_handler(int signum) {
  // close socket
  if (sockfd != -1) close(sockfd);
  if (peerfd != -1) close(peerfd);
  if (bio != NULL) wolfSSL_BIO_free(bio);
  if (pubkey != NULL) EVP_PKEY_free(pubkey);
  if (data != NULL) free(data);

  exit(signum);
}

int main(int argc, char *argv[]) {
  int ret = EXIT_SUCCESS;
  struct timespec now = {-1, -1};
  struct sockaddr_in servaddr, cliaddr;
  char client_ip[16]; // at most: xxx.xxx.xxx.xxx\0

  // register handler
  signal(SIGINT, signal_handler);
  signal(SIGKILL, signal_handler);
  signal(SIGTERM, signal_handler);

  // TESLA
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  if (argc < 3) {
    fprintf(stderr, "not enough arguments\n");
    ret = EXIT_FAILURE;
    goto out;
  }

  // certificate
  bio = wolfSSL_BIO_new_file(argv[1], "rb");
  if (!bio) {
    perror("wolfSSL_BIO_new_file failed");
    ret = EXIT_FAILURE;
    goto out;
  }
  pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (!pubkey) {
    fprintf(stderr, "cannot read the public key\n");
    ret = EXIT_FAILURE;
    goto out;
  }
  wolfSSL_BIO_free(bio);
  bio = NULL;

  // client IP
  memcpy(client_ip, argv[2], MIN(strlen(argv[2]), 15) + 1);
  client_ip[15] = '\0';

  client_alloc(&receiver);
  client_set_pkey(&receiver, pubkey);

  //generate a random nonce
  *(((int32 *) &rnonce) + 1) = (int32) time(NULL);
  rnonce += clock();
  //just to make this hard predict, xor with something weird from memory
  data = malloc(sizeof(int64));
  rnonce = rnonce ^ *(int64 *) data;
  free(data);
  data = NULL;
  //store it in the client session
  client_set_nonce(&(receiver), rnonce);

  // Creating socket for bootstrapping
  if ((peerfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket creation failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  memset(&cliaddr, 0, sizeof(cliaddr));
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_port = htons(SENDER_PORT);
//  cliaddr.sin_addr.s_addr = INADDR_LOOPBACK;
//  cliaddr.sin_addr.s_addr = inet_addr("172.50.1.2");
  cliaddr.sin_addr.s_addr = inet_addr(client_ip);
  printf("connect %s:%d\n", client_ip, SENDER_PORT);
  if (connect(peerfd, (struct sockaddr *) &cliaddr, sizeof(cliaddr)) < 0) {
    perror("socket connect failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  // TESLA: nonce
  {
    int32_t s = htonl(client_nonce_len(&receiver));
    int psize = sizeof(s) + client_nonce_len(&receiver);
    data = malloc(psize);
    memcpy(data, &s, sizeof(s));
    rc = client_write_nonce(&receiver, data + sizeof(s), client_nonce_len(&receiver));
    if (rc != TESLA_OK) {
      fprintf(stderr, "client_write_nonce failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }

    printf("sending nonce\n");
    if (send(peerfd, data, psize, 0) < 0) {
      perror("socket send failed");
      ret = EXIT_FAILURE;
      goto out;
    }

    free(data);
    data = NULL;
  }

  // TESLA: signature
  {
    int32_t s;
    int len = recv(peerfd, &s, sizeof(s), MSG_WAITALL);
    if (len != 4) {
      perror("socket recv failed");
      ret = EXIT_FAILURE;
      goto out;
    }

    s = ntohl(s);
    if (s > 1024) {
      fprintf(stderr, "buffer is too large\n");
      ret = EXIT_FAILURE;
      goto out;
    }
    data = malloc(s);
    len = recv(peerfd, data, s, MSG_WAITALL);
    if (len != s) {
      perror("socket recv failed");
      ret = EXIT_FAILURE;
      goto out;
    }

    rc = client_read_sig_tag(&receiver, data, s);
    if (rc != TESLA_OK) {
      fprintf(stderr, "client_read_sig_tag failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }
    printf("bootstrapped signature tag successfully\n");

    free(data);
    data = NULL;
  }
  close(peerfd);
  peerfd = -1;


  // Creating socket file descriptor
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));

  // Filling server information
  servaddr.sin_family = AF_INET; // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(RECEIVER_PORT);

  // Bind the socket with the server address
  if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
    perror("socket bind failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  ssize_t n;
  socklen_t len = sizeof(cliaddr); // len is value/result

  // Preparing the packet buffer
  tesla_auth_tag mtag;
  int dlen = client_auth_tag_size(&receiver);
  data = malloc(dlen + 32);
  rc = client_auth_tag_alloc(&receiver, &mtag);
  if (rc != TESLA_OK) {
    fprintf(stderr, "client_auth_tag_alloc failed\n");
    ret = EXIT_FAILURE;
    goto out;
  }

  printf("waiting for data\n");
  while (1) {
    n = recvfrom(
        sockfd, (char *) data, dlen + 32, MSG_WAITALL,
        (struct sockaddr *) &cliaddr, &len);
    if (n < 0) {
      perror("socket recvfrom failed");
      ret = EXIT_FAILURE;
      goto out;
    }

    //read the authentication tag
    rc = client_read_auth_tag(&mtag, &receiver, data + n - dlen, dlen);
    switch (rc) {
      case TESLA_OK: break;
      case TESLA_ERR_TIME_EXPIRED: {
        /*According to the client, the key in the message could not
          have been sent by the server according to the maximum
          amount of time given to packet transmission */
        fprintf(stderr, "the message violated the security condition\n");
        continue;
      }
      case TESLA_ERR_KEY_INVALID: {
        /*Indicates that the key in the tag did not match the stored
          key, the message has probably been tampered with */
        fprintf(stderr, "the key in the message was invalid");
        continue;
      }
      default: {
        ret = EXIT_FAILURE;
        goto out;
      }
    }

    rc = client_buffer(&receiver, &mtag, data, n - dlen);
    if (rc != TESLA_OK) {
      fprintf(stderr, "client_buffer failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }

    rc = client_authenticate(&receiver, &mtag);
    if (rc != TESLA_OK) {
      fprintf(stderr, "client_authenticate failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }

    {
      int mlen = 0;
      uint32_t con = 0;
      char *msg;
      /* Get the good messages */
      while ((msg = client_get_msg(&receiver, &mlen)) != NULL) {
        // record the processing time
        if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
          perror("clock_gettime failed");
          ret = EXIT_FAILURE;
          goto out;
        }
        memcpy(&con, msg + mlen - sizeof(con), sizeof(con));
        printf("%lld.%.9ld: %u : %d bytes (good)\n", (long long) now.tv_sec, now.tv_nsec, con, mlen);
        //tesla hands back dynamically allocated data
        free(msg);
      }
      /* Get the bad messages */
      while ((msg = client_get_bad_msg(&receiver, &mlen)) != NULL) {
        // record the processing time
        if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
          perror("clock_gettime failed");
          ret = EXIT_FAILURE;
          goto out;
        }
        memcpy(&con, msg + mlen - sizeof(con), sizeof(con));
        printf("%lld.%.9ld: %u : %d bytes (bad)\n", (long long) now.tv_sec, now.tv_nsec, con, mlen);
        //tesla hands back dynamically allocated data
        free(msg);
      }
    }

//    printf("Client: %ld bytes\n", n);
//    for (int i = 0; i < n; ++i) {
//      printf("%02X ", buffer[i]);
//    }
//    printf("\n\n");
  }

out:
  if (data != NULL)
    free(data);
  if (pubkey != NULL)
    EVP_PKEY_free(pubkey);
  if (bio != NULL)
    wolfSSL_BIO_free(bio);
  if (sockfd != -1)
    close(sockfd);
  return ret;
}
