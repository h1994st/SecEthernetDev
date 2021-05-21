// Client side implementation of UDP client-server model
#include <linux/can.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "common.h"
#include <assert.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sender.h>
#include <tesla.h>

//#define T_INT 1000
//#define D_INT 3
#define T_INT 10
#define D_INT 2

#define NANOSECONDS_PER_SECOND 1000000000L

int main(int argc, char *argv[]) {
  int ret = EXIT_SUCCESS;
  int ifindex = 0;// -i iface
  char ifname[IF_NAMESIZE];
  size_t ifname_len;
  int broadcast = 0; // -b
  int interval = 100;// -c millisec, default: 100 ms
  double speed = 1;  // -s speed
  int repeat = 1;    // -r repeat

  int sockfd = -1;
  struct sockaddr_in servaddr;

  // TESLA
  tesla_sender_session sender;
  NTP_t T_int;
  TESLA_ERR rc;
  FILE *pfile = NULL; // -f private_key_file
  EVP_PKEY *pkey = NULL;
  char *data = NULL;
  int mysockfd = -1;
  int peerfd = -1;
  struct sockaddr_in myaddr, peeraddr;
  socklen_t addrlen = sizeof(peeraddr);
  uint32_t peerip;
  int32_t dlen = 0;
  int32_t nlen = 0;
  char nonce_buffer[1024];

  // Parsing command-line options
  int opt;
  while ((opt = getopt(argc, argv, "i:bc:s:r:f:")) != -1) {
    //  while ((opt = getopt(argc, argv, "bc:s:r:")) != -1) {
    switch (opt) {
      case 'i': {
        ifindex = if_nametoindex(optarg);
        if (ifindex == 0) {
          perror("if_nametoindex failed");
          ret = EXIT_FAILURE;
          goto out;
        }
        ifname_len = strlen(optarg);
        memcpy(ifname, optarg, ifname_len + 1);
        break;
      }
      case 'b': {
        broadcast = 1;
        break;
      }
      case 'c': {
        interval = atoi(optarg);
        if (interval < 0) {
          fprintf(stderr, "interval must be non-negative integer\n");
          ret = EXIT_FAILURE;
          goto out;
        }
        break;
      }
      case 's': {
        speed = strtod(optarg, NULL);
        if (speed < 0) {
          fprintf(stderr, "speed must be positive\n");
          ret = EXIT_FAILURE;
          goto out;
        }
        break;
      }
      case 'r': {
        repeat = atoi(optarg);
        if (repeat != -1 && repeat <= 0) {
          fprintf(stderr, "repeat must be positive integer or -1\n");
          ret = EXIT_FAILURE;
          goto out;
        }
        break;
      }
      case 'f': {
        pfile = fopen(optarg, "rb");
        if (!pfile) {
          perror("fopen failed");
          ret = EXIT_FAILURE;
          goto out;
        }
        break;
      }
      default: {
        fprintf(stderr, "unknown command-line options\n");
        ret = EXIT_FAILURE;
        goto out;
      }
    }
  }

  // TESLA
  if (!pfile) {
    fprintf(stderr, "must provide the private key file!\n");
    ret = EXIT_FAILURE;
    goto out;
  }

  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();
  X509V3_add_standard_extensions();

  pkey = PEM_read_PrivateKey(pfile, NULL, NULL, NULL);
  if (!pkey) {
    fprintf(stderr, "cannot read the private key\n");
    ret = EXIT_FAILURE;
    goto out;
  }
  fclose(pfile);
  pfile = NULL;

  T_int = NTP_fromMillis(T_INT);
  data = malloc(DEFAULT_KEYL);
  rc = sender_init(&sender, &T_int, D_INT, 2500, data);
  free(data);
  data = NULL;
  if (rc != TESLA_OK) {
    fprintf(stderr, "sender_init failed\n");
    ret = EXIT_FAILURE;
    goto out;
  }
  sender_set_pkey(&sender, pkey);

  // Creating socket for incoming connections
  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(SENDER_PORT);

  if ((mysockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket creation failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  if (bind(mysockfd, (struct sockaddr *) &myaddr, sizeof(myaddr)) < 0) {
    perror("socket bind failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  if (listen(mysockfd, 5) < 0) {
    perror("socket listen failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  printf("Waiting for incoming connections on port %d\n", SENDER_PORT);
  while ((peerfd = accept(mysockfd, (struct sockaddr *) &peeraddr, &addrlen)) < 0) {
    perror("socket accept failed");
    ret = EXIT_FAILURE;
    goto out;
  }
  peerip = ntohl(peeraddr.sin_addr.s_addr);
  printf(
      "connection from %u.%u.%u.%u:%u\n",
      IP_ADDR_FORMAT(peerip), ntohs(peeraddr.sin_port));

  sender_start(&sender);
  // TESLA: nonce
  {
    if (recv(peerfd, &nlen, sizeof(nlen), MSG_WAITALL) < 0) {
      fprintf(stderr, "socket recv failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }
    nlen = ntohl(nlen);
    if (nlen > 1024) {
      fprintf(stderr, "buffer is too large\n");
      ret = EXIT_FAILURE;
      goto out;
    }
    printf("receiving nonce: %d bytes\n", nlen);
    if (recv(peerfd, nonce_buffer, nlen, MSG_WAITALL) < 0) {
      fprintf(stderr, "socket recv failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }
    printf("nonce received\n");
  }

  dlen = 4 + sender_sig_tag_size(&sender);
  data = malloc(dlen);
  // TESLA: send the signature tag
  {
    int32_t s = sender_sig_tag_size(&sender);
    printf("sending signature tag\n");
    s = htonl(s);
    memcpy(data, &s, sizeof(s));

    rc = sender_write_sig_tag(&sender, data + 4, dlen - 4, nonce_buffer, nlen);
    if (rc != TESLA_OK) {
      fprintf(stderr, "sender_write_sig_tag failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }

    if (send(peerfd, data, dlen, 0) < 0) {
      fprintf(stderr, "socket send failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }
  }
  free(data);
  data = NULL;
  close(peerfd);
  peerfd = -1;
  close(mysockfd);
  mysockfd = -1;

  // Creating socket to the server
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  // Binding to an interface
  if (ifindex != 0) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, ifname_len)
        == -1) {
      perror("setsockopt failed");
      ret = EXIT_FAILURE;
      goto out;
    }
  }

  // Setting broadcast
  if (broadcast != 0) {
    // `broadcast` should not have `bool` type, which will result in an error
    // of "invalid argument"
    // - `sizeof(bool)` depends on implementations
    if (setsockopt(
            sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast))
        == -1) {
      perror("setsockopt failed");
      ret = EXIT_FAILURE;
      goto out;
    }
  }

  struct timespec deadline = {};
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
    perror("clock_gettime failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  // Filling server information
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(RECEIVER_PORT);
//  servaddr.sin_addr.s_addr = INADDR_LOOPBACK; // TODO: change back to broadcast
  servaddr.sin_addr.s_addr = INADDR_BROADCAST;

  // Preparing the packet buffer
  dlen = sender_auth_tag_size(&sender);
  data = malloc(dlen + 32);

  ssize_t len;
  ssize_t n;
  uint32_t con = 0;

  for (int i = 0; repeat == -1 || i < repeat; ++i) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline_with_tstamp_precision(
        argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);
    if (!handle) {
      fprintf(stderr, "pcap_open failed: %s\n", errbuf);
      ret = EXIT_FAILURE;
      goto out;
    }

    struct timespec start = {-1, -1};
    struct timespec pcap_start = {-1, -1};

    struct pcap_pkthdr header;
    const u_char *p;
    struct can_frame *can;
    while ((p = pcap_next(handle, &header))) {
      if (start.tv_nsec == -1) {
        if (clock_gettime(CLOCK_MONOTONIC, &start) == -1) {
          perror("clock_gettime failed");
          ret = EXIT_FAILURE;
          pcap_close(handle);
          goto out;
        }
        pcap_start.tv_sec = header.ts.tv_sec;
        // ???: do we need to convert this, as we use PCAP_TSTAMP_PRECISION_NANO
        pcap_start.tv_nsec = header.ts.tv_usec;
      }

      // skip the first 16 bytes, Linux cooked capture v1 header
      // https://wiki.wireshark.org/SLL
      p += 16;
      can = (struct can_frame *) p;

      if (interval != -1) {
        // Use constant packet rate
        deadline.tv_sec += interval / 1000L;
        deadline.tv_nsec += (interval * 1000000L) % NANOSECONDS_PER_SECOND;
      }

      if (deadline.tv_nsec > NANOSECONDS_PER_SECOND) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= NANOSECONDS_PER_SECOND;
      }

      struct timespec now = {-1, -1};
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        perror("clock_gettime failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }

      // sleep
      if (deadline.tv_sec > now.tv_sec || (deadline.tv_sec == now.tv_sec && deadline.tv_nsec > now.tv_nsec)) {
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL)
            != 0) {
          perror("clock_nanosleep failed");
          ret = EXIT_FAILURE;
          pcap_close(handle);
          goto out;
        }
      }

      len = sizeof(struct can_frame) - CAN_MAX_DLEN + can->can_dlc;
      assert(len + sizeof(con) <= 32); // hard coded
      memcpy(data, p, len);
      memcpy(data + len, &con, sizeof(con)); // attach a counter
      rc = sender_write_auth_tag(
          &sender, data, len + sizeof(con), data + len + sizeof(con), dlen);
      if (rc != TESLA_OK) {
        fprintf(stderr, "sender_write_auth_tag failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }

      // record the sending time
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        perror("clock_gettime failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }
      printf(
          "%lld.%.9ld: %u : %ld + %d bytes\n", (long long) now.tv_sec, now.tv_nsec, con, len, dlen);

      n = sendto(
          sockfd, data, len + sizeof(con) + dlen, MSG_CONFIRM,
          (struct sockaddr *) &servaddr, sizeof(servaddr));
      if (n != len + sizeof(con) + dlen) {
        perror("sendto failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }
      ++con; // increase the counter
    }

    pcap_close(handle);
  }

out:
  ctx_print_err(&(sender.ctx));

  if (pkey != NULL)
    EVP_PKEY_free(pkey);
  if (data != NULL)
    free(data);
  if (pfile != NULL)
    fclose(pfile);
  if (mysockfd != -1)
    close(mysockfd);
  if (sockfd != -1)
    close(sockfd);
  if (peerfd != -1)
    close(peerfd);

  return ret;
}
