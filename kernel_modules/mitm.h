//
// Created by h1994st on 4/15/21.
//

#ifndef SECETHERNETDEV_MITM_H
#define SECETHERNETDEV_MITM_H

#include <crypto/akcipher.h>
#include <crypto/sha.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/version.h>
#include <net/sch_generic.h>

#if MITM_ROLE == 1
#ifdef MITM_DOS_PROTECTION
#include "time_lock_puzzle.h"
#endif /* MITM_DOS_PROTECTION */
#endif /* MITM_ROLE == 1 */

/*
 * enum mitm_handler_result - Possible return values for handlers.
 * @MITM_CONSUMED: skb was consumed by handler, do not process it further.
 * @MITM_FORWARD:  forward to paired device.
 * @MITM_REPLY:    reply through same device (only slave supported)
 * @MITM_DROP:     Drop the packet
 */
enum mitm_handler_result { MITM_CONSUMED, MITM_FORWARD, MITM_REPLY, MITM_DROP };

extern u8 hmac_key[SHA256_DIGEST_SIZE];
#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
#define MITM_PROOF_RSA_KEY_LEN 1191
extern u8 proof_key[MITM_PROOF_RSA_KEY_LEN];
#else
// TODO: we actually need an array to store keys for each slave device
extern u8 proof_key[SHA256_DIGEST_SIZE];
#endif /* MITM_AUTH_RSA */
#endif

/*
 * This structure is private to each device. It is used to pass
 * packets in and out, so there is place for a packet
 */
struct mitm {
  struct crypto_shash *hmac_shash;
#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
  struct crypto_akcipher *proof_akcipher;
  struct akcipher_request *proof_req;
  uint8_t *xbuf[2];
#else
  struct crypto_shash *proof_shash;
#endif /* MITM_AUTH_RSA */
#endif /* MITM_ROLE == 2 */
#if MITM_ROLE == 1 || MITM_ROLE == 2
  struct crypto_shash *hash_shash;
#endif /* MITM_ROLE == 1 || MITM_ROLE == 2 */
  struct net_device *dev;
  spinlock_t lock;

#if MITM_ROLE == 1
#ifdef MITM_DOS_PROTECTION
  struct timer_list net_monitor_timer;
  time_lock_puzzle_ctx *puzzle;
  time_lock_puzzle *payload;
#endif /* MITM_DOS_PROTECTION */
#endif /* MITM_ROLE == 1 */

  enum mitm_handler_result (*handle_ingress)(
      struct mitm *mitm, struct sk_buff *skb);
  enum mitm_handler_result (*handle_egress)(
      struct mitm *mitm, struct sk_buff *skb);

#ifdef CONFIG_NETPOLL
  struct netpoll np;
#endif
  netdev_tx_t (*xmit)(struct mitm *mitm, struct sk_buff *);

  struct slave {
    struct net_device *dev;
  } slave;
};

#define mitm_slave_list(mitm) (&(mitm)->dev->adj_list.lower)
#define mitm_has_slave(mitm) (!list_empty(mitm_slave_list(mitm)))
static inline struct slave *mitm_slave(struct mitm *mitm) {
  if (!mitm_has_slave(mitm)) return NULL;
  return netdev_adjacent_get_private(mitm_slave_list(mitm)->next);
}
#define mitm_of(slaveptr) container_of((slaveptr), struct mitm, slave)

#endif  //SECETHERNETDEV_MITM_H
