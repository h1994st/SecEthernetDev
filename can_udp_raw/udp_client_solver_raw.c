// Client side implementation of UDP client-server model
#include <arpa/inet.h>
#include <assert.h>
#include <linux/can.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "gk_crypto.h"

#define PORT 8080
#define MAXLINE (14 + 152)
uint8_t buffer[MAXLINE];

// the functionality of replaying pcap files is borrowed from
// https://github.com/rigtorp/udpreplay/blob/master/src/udpreplay.cpp

#define NANOSECONDS_PER_SECOND 1000000000L

static uint8_t data[256];

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr, int nbytes) {
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum = 0;
  while (nbytes > 1) {
    sum += *(ptr++);
    nbytes -= 2;
  }
  if (nbytes == 1) {
    oddbyte = 0;
    *((u_char *) &oddbyte) = *(u_char *) ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = (short) ~sum;

  return (answer);
}

// Driver code
int main(int argc, char *argv[]) {
  int ret = EXIT_SUCCESS;
  int ifindex = 0;  // -i iface
  char ifname[IF_NAMESIZE];
  size_t ifname_len;
  int broadcast = 0;   // -b
  int interval = 100;  // -c millisec, default: 100 ms
  double speed = 1;    // -s speed
  int repeat = 1;      // -r repeat

  int sockfd;
  struct sockaddr_ll servaddr, auth_addr;
  socklen_t auth_addr_len = sizeof(auth_addr);
  struct timeval tv;
  struct ether_header *puzzle_eth = (struct ether_header *) buffer;

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&auth_addr, 0, sizeof(auth_addr));

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
        servaddr.sll_ifindex = ifindex;
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
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }
  servaddr.sll_family = AF_PACKET;

  // Binding to an interface
  if (ifindex != 0) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifname, ifname_len)
        == -1) {
      perror("setsockopt failed");
      ret = EXIT_FAILURE;
      goto out;
    }

    // obtain MAC address for the interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, IF_NAMESIZE);
    if (ioctl(sockfd, SIOCGIFHWADDR, (void *) &ifr) < 0) {
      perror("ioctl SIOCGIFHWADDR failed");
      ret = EXIT_FAILURE;
      goto out;
    }
    servaddr.sll_halen = ETH_ALEN;
    memcpy(servaddr.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
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
    servaddr.sll_pkttype = PACKET_BROADCAST;
  }

  // Set receive timeout
  tv.tv_sec = 0;
  tv.tv_usec = 100000;  // 100 ms
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof(tv));

  struct timespec deadline = {};
  if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
    perror("clock_gettime failed");
    ret = EXIT_FAILURE;
    goto out;
  }

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
    struct ether_header *eth = (struct ether_header *) data;
    struct ip *iph = (struct ip *) (data + sizeof(struct ether_header));
    struct udphdr *udph =
        (struct udphdr
             *) (data + sizeof(struct ether_header) + sizeof(struct ip));  // fixed 20 bytes of IP header
    uint8_t *payload =
        (data + sizeof(struct ether_header) + sizeof(struct ip)
         + sizeof(struct udphdr));
    memset(data, 0, sizeof(data));
    // fill parts of the packet buffer
    memcpy(
        eth->ether_shost, servaddr.sll_addr, ETH_ALEN);  // client's MAC address
    memset(eth->ether_dhost, 0xff, ETH_ALEN);            // broadcast
    eth->ether_type = htons(ETH_P_IP);
    iph->ip_v = IPVERSION;
    iph->ip_hl = 5;  // fixed 20 bytes, no options
    iph->ip_id = 0;
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src.s_addr = inet_addr("172.50.1.2");  // fixed source IP
    iph->ip_dst.s_addr = INADDR_BROADCAST;
    udph->source = htons(8080);
    udph->dest = htons(8080);

    // counter
    uint32_t con = 0;
    ssize_t len, n;

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

      len = sizeof(struct can_frame) - CAN_MAX_DLEN
          + can->can_dlc;  // can frame length
      memcpy(payload, p, len);
      memcpy(
          payload + len, &con,
          sizeof(con));  // append the counter to the end of the udp payload
      len += sizeof(con);

      // adjust length fields
      iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + len);
      udph->len = htons(sizeof(struct udphdr) + len);

      // calculate IP checksum
      iph->ip_sum = 0;  // reset to zero
      iph->ip_sum =
          csum((unsigned short *) iph, 4 * iph->ip_hl);  // fill ip checksum
      udph->check = 0;                                   // not used
      len += sizeof(struct ether_header) + sizeof(struct ip)
          + sizeof(struct udphdr);  // adjust to total buffer length

      // calculate MAC over the whole Ethernet frame
      gk_hmac_sha256(data, len, data + len, GK_SENDER_KEY);
      len += GK_MAC_LEN;
      assert(len <= sizeof(data));

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
      if (deadline.tv_sec > now.tv_sec
          || (deadline.tv_sec == now.tv_sec
              && deadline.tv_nsec > now.tv_nsec)) {
        if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL)
            != 0) {
          perror("clock_nanosleep failed");
          ret = EXIT_FAILURE;
          pcap_close(handle);
          goto out;
        }
      }

      // record the sending time
      if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        perror("clock_gettime failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }
      printf(
          "%lld.%.9ld: %u : %ld bytes\n", (long long) now.tv_sec, now.tv_nsec,
          con, len);

      n = sendto(
          sockfd, data, len, 0, (const struct sockaddr *) &servaddr,
          sizeof(servaddr));
      if (n != len) {
        perror("sendto failed");
        ret = EXIT_FAILURE;
        pcap_close(handle);
        goto out;
      }

      ++con;

      // receive puzzle
      n = recvfrom(
          sockfd, (char *) buffer, MAXLINE, 0, (struct sockaddr *) &auth_addr,
          &auth_addr_len);
      if (n == -1) {
        // receive error?
        fprintf(stderr, "receive nothing\n");
        continue;
      }

      fprintf(stderr, "receive %zd bytes\n", n);

      if (n == MAXLINE) {
        if (ntohs(puzzle_eth->ether_type) == GK_ETHTYPE_PUZZLE) {
          // puzzle
          fprintf(stderr, "solving puzzle\n");
          uint64_t solution = gk_solve_puzzle(
              (struct time_lock_puzzle *) puzzle_eth
                  + sizeof(struct ether_header),
              &ret);
          if (ret == -1) {
            // solving error
            // should exit
            perror("solving failed");
            ret = EXIT_FAILURE;
            pcap_close(handle);
            goto out;
          }

          // send the solution back
          fprintf(stderr, "send puzzle solution: %lu\n", solution);
          memcpy(puzzle_eth->ether_dhost, puzzle_eth->ether_shost, ETH_ALEN);
          memcpy(
              puzzle_eth->ether_shost, servaddr.sll_addr,
              ETH_ALEN);  // client's MAC address
          puzzle_eth->ether_type = GK_ETHTYPE_PUZZLE_SOLUTION;

          memcpy(
              buffer + sizeof(struct ether_header), &solution,
              sizeof(uint64_t));

          n = sendto(
              sockfd, buffer, sizeof(struct ether_header) + sizeof(uint64_t), 0,
              (const struct sockaddr *) &auth_addr, sizeof(auth_addr));
          if (n != len) {
            perror("sendto solution failed");
            ret = EXIT_FAILURE;
            pcap_close(handle);
            goto out;
          }
        }
      }
    }

    pcap_close(handle);
  }

out:
  close(sockfd);
  return ret;
}
