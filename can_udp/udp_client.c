// Client side implementation of UDP client-server model
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/can.h>
#include <net/if.h>

#include <pcap/pcap.h>

#define PORT    8080
#define MAXLINE 1024

// the functionality of replaying pcap files is borrowed from
// https://github.com/rigtorp/udpreplay/blob/master/src/udpreplay.cpp

#define NANOSECONDS_PER_SECOND 1000000000L

// Driver code
int main(int argc, char *argv[]) {
  int ret = EXIT_SUCCESS;
  int ifindex = 0; // -i iface
  char ifname[IF_NAMESIZE];
  size_t ifname_len;
  int broadcast = 0; // -b
  int interval = 100; // -c millisec, default: 100 ms
  double speed = 1; // -s speed
  int repeat = 1; // -r repeat

  int sockfd;
  struct sockaddr_in servaddr;

  // Parsing command-line options
  int opt;
  while ((opt = getopt(argc, argv, "i:bc:s:r:")) != -1) {
//  while ((opt = getopt(argc, argv, "bc:s:r:")) != -1) {
    switch (opt) {
      case 'i': {
        ifindex = if_nametoindex(optarg);
        if (ifindex == 0) {
          perror("if_nametoindex failed");
          exit(EXIT_FAILURE);
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
          exit(EXIT_FAILURE);
        }
        break;
      }
      case 's': {
        speed = strtod(optarg, NULL);
        if (speed < 0) {
          fprintf(stderr, "speed must be positive\n");
          exit(EXIT_FAILURE);
        }
        break;
      }
      case 'r': {
        repeat = atoi(optarg);
        if (repeat != -1 && repeat <= 0) {
          fprintf(stderr, "repeat must be positive integer or -1\n");
          exit(EXIT_FAILURE);
        }
        break;
      }
      default: {
        fprintf(stderr, "unknown command-line options\n");
        exit(EXIT_FAILURE);
      }
    }
  }

  // Creating socket file descriptor
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
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

  memset(&servaddr, 0, sizeof(servaddr));

  // Filling server information
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
//  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_addr.s_addr = INADDR_BROADCAST;

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
      if (deadline.tv_sec > now.tv_sec ||
          (deadline.tv_sec == now.tv_sec && deadline.tv_nsec > now.tv_nsec)) {
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL)
            != 0) {
          perror("clock_nanosleep failed");
          ret = EXIT_FAILURE;
          pcap_close(handle);
          goto out;
        }
      }

      ssize_t len = sizeof(struct can_frame) - CAN_MAX_DLEN + can->can_dlc;
      ssize_t n;

      // record the sending time
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        perror("clock_gettime failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }
      printf(
          "%lld.%.9ld: %ld bytes\n", (long long) now.tv_sec, now.tv_nsec, len);

      n = sendto(
          sockfd, p, len, MSG_CONFIRM,
          (const struct sockaddr *) &servaddr, sizeof(servaddr));
      if (n != len) {
        perror("sendto failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }
    }

    pcap_close(handle);
  }

out:
  close(sockfd);
  return ret;
}
