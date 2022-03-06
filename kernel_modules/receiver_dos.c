//
// Created by h1994st on 4/15/21.
//

#include "receiver_dos.h"
#include "proof.h"

#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/rhashtable.h>
#include <linux/udp.h>

#if (MITM_ROLE != 1)
#error "Wrong MITM_ROLE! Should be 1"
#endif

static u8 data[SHA256_DIGEST_SIZE] __maybe_unused = {
    0x00};  // a temporary place to store hash/MAC data
u8 hmac_key[SHA256_DIGEST_SIZE] = {0x01};

#if !defined(MITM_DOS_PROTECTION)
#error "Must define MITM_DOS_PROTECTION"
#endif

#include "mpi/mpi.h"
#include "time_lock_puzzle.h"
#include <linux/timer.h>

#ifdef MITM_DOS_PROTECTION
// store bytes received for every connected ports
u64 dev_rx_bytes[NET_MONITOR_MAX_NUM] = {0x00};
u8 dev_states[NET_MONITOR_MAX_NUM] = {0x00};  // 0: normal, 1: stop
u64 dev_solutions[NET_MONITOR_MAX_NUM] = {0x00};

static u8 monitor_start = 0;

/* Network monitor callback */
void net_monitor_cb(struct timer_list *timer) {
  int err;
  int i = 0;
  struct mitm *mitm = from_timer(mitm, timer, net_monitor_timer);
  struct slave *slave = mitm_slave(mitm);
  struct net_device *slave_dev = slave->dev;
  struct rtnl_link_stats64 stats;
  u64 rx_bps;
  u64 solution;
  struct sk_buff *skbn;  // new skb
  u8 *puzzle_payload;
  int hlen;
  int tlen;
  unsigned int plen = sizeof(time_lock_puzzle);
  struct ethhdr *eth;

  err = mod_timer(timer, jiffies + msecs_to_jiffies(NET_MONITOR_DELAY));
  if (err) {
    netdev_err(mitm->dev, "Failed to set timer\n");
    return;
  }

  if (monitor_start == 0) {
    // just continue
    // no report
    return;
  }

  // retrieve traffic stats
  dev_get_stats(slave_dev, &stats);

  if (stats.rx_bytes == dev_rx_bytes[i]) return;

  rx_bps = (stats.rx_bytes - dev_rx_bytes[i]) * 8 * 1000 / NET_MONITOR_DELAY;
  netdev_info(
      mitm->dev, "throughput (%s): %llu bps\n", slave_dev->name, rx_bps);

  dev_rx_bytes[i] = stats.rx_bytes;

  if (dev_states[i] == 1) {
    // has been blocked
    return;
  }

  if (rx_bps <= 6000) {
    // no problem
    return;
  }

  netdev_info(
      mitm->dev, "throughput (%s), %llu bps, is greater than the threshold\n",
      slave_dev->name, rx_bps);

  // block the port
  dev_states[i] = 1;

  // generate the puzzle
  err = time_lock_puzzle_generate(mitm->puzzle, 10, mitm->payload, &solution);
  if (err) {
    netdev_err(mitm->dev, "failed to generate the puzzle: %d\n", err);
    return;
  }
  netdev_info(mitm->dev, "puzzle solution: %llu\n", solution);
  dev_solutions[i] = solution;

  // send the puzzle
  // create `skbn` as a template
  hlen = LL_RESERVED_SPACE(slave_dev);
  tlen = slave_dev->needed_tailroom;
  skbn = alloc_skb(plen + hlen + tlen, GFP_ATOMIC);
  if (!skbn) {
    netdev_err(mitm->dev, "cannot allocate sk_buff for puzzle\n");
    return;
  }

  skb_reserve(skbn, hlen);
  skb_reset_network_header(skbn);  // now points to the proof header
  puzzle_payload = skb_put_data(skbn, mitm->payload, plen);
  skbn->protocol = htons(ETH_P_MITM_PUZZLE);
  skbn->dev = slave_dev;
  skbn->pkt_type = PACKET_OUTGOING;

  eth = skb_push(skbn, ETH_HLEN);
  eth->h_proto = htons(ETH_P_MITM_PUZZLE);
  eth_broadcast_addr(eth->h_dest);  // broadcast destination
  memcpy(
      eth->h_source, slave_dev->dev_addr,
      ETH_ALEN);  // use the MAC address of the slave device
  skb_reset_mac_header(skbn);

  err = dev_queue_xmit(skbn);
  netdev_info(mitm->dev, "puzzle: dev_queue_xmit() returns %d\n", err);
}
#endif /* MITM_DOS_PROTECTION */

enum mitm_handler_result
handle_puzzle_solution(struct mitm *mitm, struct sk_buff *skb) {
  uint8_t *header = skb_mac_header(skb);
  uint64_t *solution_ptr = (uint64_t *) (header + sizeof(struct ethhdr));
  uint64_t solution = *solution_ptr;

  if (solution == dev_solutions[0]) {
    netdev_info(mitm->dev, "correct solution!\n");
    // clear the solution
    dev_solutions[0] = 0;
    // unblock
    dev_states[0] = 0;
  } else {
    netdev_info(mitm->dev, "wrong solution: %llu!\n", solution);
  }

  return MITM_CONSUMED;
}

enum mitm_handler_result
mitm_from_slave(struct mitm *mitm, struct sk_buff *skb) {
  uint16_t protocol = ntohs(vlan_get_protocol(skb));
  uint8_t *header = skb_mac_header(skb);
  struct slave *slave = mitm_slave(mitm);
  struct net_device *slave_dev = slave->dev;
  // `skb->dev` is not the source device, because `br_pass_frame_up` has already
  // changed this field to the bridge device
  struct net_device *src_dev = slave_dev;

  // If IPv4...
  if (protocol == ETH_P_IP) {
    // Find IP header.
    struct iphdr *iph = ip_hdr(skb);
    struct ethhdr *eth = (struct ethhdr *) header;
    bool is_broadcast = is_broadcast_ether_addr(eth->h_dest);
    // UDP ...
    if (iph->protocol == IPPROTO_UDP && is_broadcast) {
      int i = 0;

      netdev_info(mitm->dev, "Observe incoming broadcast UDP packets\n");

      if (monitor_start == 0) {
        // receive a packet, start monitoring
        monitor_start = 1;
      }

      if (dev_states[i] == 1) {
        netdev_warn(
            mitm->dev, "drop packets from port %d (%s)\n", i, src_dev->name);
        return MITM_DROP;
      }

      return MITM_FORWARD;
    }
  } else if (protocol == ETH_P_MITM_PUZZLE_SOLUTION) {
    return handle_puzzle_solution(mitm, skb);
  }

  return MITM_FORWARD;
}

enum mitm_handler_result
mitm_from_master(struct mitm *mitm, struct sk_buff *skb) {
  return MITM_FORWARD;
}
