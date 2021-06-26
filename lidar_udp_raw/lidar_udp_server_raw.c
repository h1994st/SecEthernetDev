// Server side implementation of UDP client-server model
#include <arpa/inet.h>
#include <assert.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "gk_crypto.h"
#include "hashmap.h"

#define PORT 8080
#define MAXLINE 1400

int sockfd = -1;
uint8_t buffer[MAXLINE];
struct timespec now = {-1, -1};
struct hashmap *map = NULL;
uint8_t proof_mac_buf[GK_MAC_LEN];

struct gk_proof_hdr {
  uint8_t pkt_hash[GK_MAC_LEN];
  uint8_t proof_hmac[GK_MAC_LEN];
};

struct map_entry {
  uint8_t pkt_hash[GK_MAC_LEN];
  uint8_t *pkt_data;
  size_t pkt_len;
};

int user_compare(const void *a, const void *b, void *udata) {
  const struct map_entry *pa = a;
  const struct map_entry *pb = b;
  return memcmp(pa->pkt_hash, pb->pkt_hash, GK_MAC_LEN);
}

bool user_iter_free(const void *item, void *udata) {
  const struct map_entry *p = item;
  free(p->pkt_data);
  return true;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
  const struct map_entry *p = item;
  uint64_t h;
  memcpy(&h, p->pkt_hash, sizeof(h));

  //  printf("entry %p: %lu\n", p, h);

  return h;
}

void signal_handler(int signum) {
  // close socket
  if (sockfd != -1) close(sockfd);
  if (map != NULL) {
    hashmap_scan(map, user_iter_free, NULL);
    hashmap_free(map);
  }

  exit(signum);
}

int handle_proof_packets(uint8_t *data, size_t len) {
  uint32_t con = 0;
  struct gk_proof_hdr *proofh =
      (struct gk_proof_hdr *) (data + sizeof(struct ether_header));
  struct map_entry *entry = NULL;

  assert(len == sizeof(struct ether_header) + sizeof(struct gk_proof_hdr));

  //  printf("handle proof packet\n");

  // get stored packet
  entry = hashmap_get(
      map,
      proofh);  // we can safely pass proofh, as both structures share the same 32 bytes
  if (!entry) {
    fprintf(stderr, "no corresponding packet in the map!\n");
    return 0;
  }
  //  printf("retrieve an entry: %p\n", entry);
  //  for (int i = 0; i < entry->pkt_len; ++i) {
  //    printf("%02X ", entry->pkt_data[i]);
  //  }
  //  printf("\n");

  // calculate and verify the proof
  if (gk_hmac_sha256(
          entry->pkt_data, entry->pkt_len, proof_mac_buf, GK_RECEIVER_KEY)
      != 0) {
    fprintf(stderr, "gk_hmac_sha256 failed\n");
    return 0;
  }

  if (memcmp(proof_mac_buf, proofh->proof_hmac, GK_MAC_LEN) != 0) {
    //    for (int i = 0; i < GK_MAC_LEN; ++i) {
    //      printf("%02X ", proof_mac_buf[i]);
    //    }
    //    printf("\n");
    //    for (int i = 0; i < GK_MAC_LEN; ++i) {
    //      printf("%02X ", proofh->proof_hmac[i]);
    //    }
    //    printf("\n\n");
    fprintf(stderr, "wrong proof!\n");
    return 0;
  }

  // remove the entry
  hashmap_delete(map, entry);

  uint8_t *payload = entry->pkt_data + sizeof(struct ether_header)
      + sizeof(struct ip);  // IP payload
  struct udphdr *udph = (struct udphdr *) payload;
  memcpy(&con, payload + ntohs(udph->len) - sizeof(con), sizeof(con));

  // consume stored packet
  if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
    perror("clock_gettime failed");
    return -1;
  }
  printf(
      "%lld.%.9ld: %u : %ld bytes\n", (long long) now.tv_sec, now.tv_nsec, con,
      entry->pkt_len);

  //  printf("free: %p\n", entry->pkt_data);
  free(entry->pkt_data);
  return 0;
}

int main() {
  int ret = EXIT_SUCCESS;
  struct sockaddr_ll servaddr, cliaddr;

  // register handler
  signal(SIGINT, signal_handler);
  signal(SIGKILL, signal_handler);
  signal(SIGTERM, signal_handler);

  // Allocating hashmap
  map = hashmap_new(
      sizeof(struct map_entry), 0, 0, 0, user_hash, user_compare, NULL);
  if (!map) {
    perror("hashmap_new failed");
    exit(EXIT_FAILURE);
  }

  // Creating socket file descriptor
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
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
  if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "eth0", 4) == -1) {
    perror("setsockopt failed");
    ret = EXIT_FAILURE;
    goto out;
  }

  ssize_t n;

  socklen_t len = sizeof(cliaddr);  // len is value/resuslt
  struct ether_header *eth = (struct ether_header *) buffer;
  struct ip *iph = (struct ip *) (buffer + sizeof(struct ether_header));
  struct udphdr *udph =
      (struct udphdr
           *) (buffer + sizeof(struct ether_header) + sizeof(struct ip));  // fixed 20 bytes of IP header
  struct map_entry entry;
  memset(&entry, 0, sizeof(struct map_entry));
  while (true) {
    n = recvfrom(
        sockfd, (char *) buffer, MAXLINE, 0, (struct sockaddr *) &cliaddr,
        &len);
    if (n == -1) {
      perror("recvfrom failed");
      continue;
    }
    if (ntohs(eth->ether_type) == GK_ETHTYPE_PROOF) {
      ret = handle_proof_packets(buffer, n);
      if (ret == -1) {
        fprintf(stderr, "handle_proof_packets failed\n");
        ret = EXIT_FAILURE;
        goto out;
      }
      continue;
    }
    if (ntohs(eth->ether_type) != ETH_P_IP) {
      fprintf(stderr, "skip non-IP packets: %zd bytes!\n", n);
      continue;
    }
    if (iph->ip_dst.s_addr != INADDR_BROADCAST) {
      fprintf(stderr, "skip non-broadcast packets: %zd bytes\n", n);
      continue;
    }
    if (ntohs(udph->dest) != 8080) {
      fprintf(stderr, "wrong UDP dest port\n");
      continue;
    }

    // initialize map entry structure
    entry.pkt_data = malloc(n);
    if (!entry.pkt_data) {
      perror("malloc failed");
      ret = EXIT_FAILURE;
      goto out;
    }
    memcpy(entry.pkt_data, buffer, n);
    entry.pkt_len = n;
//    printf("allocate: %p\n", entry.pkt_data);

    // calculate hash for the whole Ethernet frame
    if (gk_sha256(buffer, n, entry.pkt_hash) != 0) {
      fprintf(stderr, "gk_sha256 failed\n");
      ret = EXIT_FAILURE;
      goto out;
    }

    // store the packet
//    printf("store the packet: %p\n", entry);
    hashmap_set(map, &entry);
    entry.pkt_data = NULL;
    entry.pkt_len = 0;
//    for (int i = 0; i < entry->pkt_len; ++i) {
//      printf("%02X ", entry->pkt_data[i]);
//    }
//    printf("\n");

    //    printf("Client: %ld bytes\n", n);
    //    for (int i = 0; i < n; ++i) {
    //      printf("%02X ", buffer[i]);
    //    }
    //    printf("\n\n");
  }

out:
  close(sockfd);
  return ret;
}
