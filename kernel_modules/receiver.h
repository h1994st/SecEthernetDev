//
// Created by h1994st on 4/15/21.
//

#ifndef SECETHERNETDEV_AUTHENTICATOR_H
#define SECETHERNETDEV_AUTHENTICATOR_H

#include "role.h"

#include <linux/rhashtable.h>

struct mitm_skb_entry {
  struct rhash_head rhnode;

  u8 skb_hash[SHA256_DIGEST_SIZE];  // key
  struct sk_buff *skb;
};

int mitm_skb_rht_init(void);
void mitm_skb_rht_fini(void);

#endif  //SECETHERNETDEV_AUTHENTICATOR_H
