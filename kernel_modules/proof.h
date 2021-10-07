//
// Created by h1994st on 4/21/21.
//

#ifndef SECETHERNETDEV_PROOF_H
#define SECETHERNETDEV_PROOF_H

#include <crypto/sha.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>

// The high byte must be greater than 0x06 (see `eth_proto_is_802_3()`
// in `linux/etherdevice.h`). Otherwise, the proof packets will be treated
// as `ETH_P_802_2` (see `eth_type_trans()` in `net/ethernet/eth.c`).
#define ETH_P_MITM_AUTH 0x080A
//#define ETH_P_MITM_AUTH ETH_P_802_3

struct proofhdr {
  unsigned char pkt_hash[SHA256_DIGEST_SIZE];
  unsigned char proof_hmac[SHA256_DIGEST_SIZE];
} __attribute__((packed));
;

static inline struct proofhdr *proof_hdr(const struct sk_buff *skb) {
  return (struct proofhdr *) skb_network_header(skb);
}

static inline unsigned int proof_hdr_len(void) {
  return sizeof(struct proofhdr);
}

#endif  //SECETHERNETDEV_PROOF_H
