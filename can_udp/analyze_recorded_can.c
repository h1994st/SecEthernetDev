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

int main(int argc, char *argv[]) {
  int ret = EXIT_SUCCESS;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline_with_tstamp_precision(
      argv[optind], PCAP_TSTAMP_PRECISION_NANO, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open failed: %s\n", errbuf);
    ret = EXIT_FAILURE;
    goto out;
  }

  struct pcap_pkthdr header;
  const u_char *p;
  struct can_frame *can;
  int32_t len;
  int32_t total_size = 0;
  int32_t n = 0;
  while ((p = pcap_next(handle, &header))) {
    // skip the first 16 bytes, Linux cooked capture v1 header
    // https://wiki.wireshark.org/SLL
    p += 16;
    can = (struct can_frame *) p;

    len = sizeof(struct can_frame) - CAN_MAX_DLEN + can->can_dlc;
    total_size += len;
    n += 1;

    printf(
        "%lld.%.9ld: %d bytes\n",
        (long long) header.ts.tv_sec, header.ts.tv_usec, len);
  }
  printf("#frame: %d\n", n);
  printf("Total size of CAN frames: %d bytes\n", total_size);

  pcap_close(handle);

out:
  return ret;
}
