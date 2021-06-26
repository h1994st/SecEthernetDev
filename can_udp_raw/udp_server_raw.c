// Server side implementation of UDP client-server model
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/can.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <signal.h>

#define PORT    8080
#define MAXLINE 256

int sockfd = -1;
uint8_t buffer[MAXLINE];

void signal_handler(int signum) {
  // close socket
  if (sockfd != -1) close(sockfd);

  exit(signum);
}

int main() {
  int ret = EXIT_SUCCESS;
  struct timespec now = {-1, -1};
  struct sockaddr_ll servaddr, cliaddr;

  // register handler
  signal(SIGINT, signal_handler);
  signal(SIGKILL, signal_handler);
  signal(SIGTERM, signal_handler);

  // Creating socket file descriptor
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
    perror("socket creation failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));

  // Bind the socket with the server address
  servaddr.sll_ifindex = if_nametoindex("eth0");
  servaddr.sll_family = AF_PACKET;
  servaddr.sll_pkttype = PACKET_BROADCAST;
  if (bind(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
    perror("bind failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  // Bind with "eth0"
  if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4)
      == -1) {
    perror("setsockopt failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  ssize_t n;

  socklen_t len = sizeof(cliaddr); // len is value/resuslt
  struct ether_header *eth = (struct ether_header*) buffer;
  struct ip *iph = (struct ip *) (buffer + sizeof(struct ether_header));
  struct udphdr *udph = (struct udphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct ip)); // fixed 20 bytes of IP header
  struct can_frame *can = (struct can_frame *) (buffer + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
  while (1) {
    n = recvfrom(
        sockfd, (char *) buffer, MAXLINE, 0,
        (struct sockaddr *) &cliaddr, &len);
    if (n == -1) {
      perror("recvfrom failed");
      continue;
    }
    if (ntohs(eth->ether_type) != ETH_P_IP) {
      fprintf(stderr, "skip non-IP packets: %zd bytes!\n", n);
      continue;
    }
    if (ntohs(udph->dest) != 8080) {
      fprintf(stderr, "wrong UDP dest port\n");
      continue;
    }

//    printf("Client: %ld bytes\n", n);
//    for (int i = 0; i < n; ++i) {
//      printf("%02X ", buffer[i]);
//    }
//    printf("\n\n");

    // record the receiving time
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
      perror("clock_gettime failed");
      ret = EXIT_FAILURE;
      goto out;
    }
    printf("%lld.%.9ld: %ld bytes\n", (long long) now.tv_sec, now.tv_nsec, n);
  }

out:
  close(sockfd);
  return ret;
}
