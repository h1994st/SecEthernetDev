//
// Created by h1994st on 4/15/21.
//

#include "authenticator_rsa.h"
#include "proof.h"

#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/mpi.h>
#include <linux/timer.h>
#include <linux/udp.h>

#include "mpi/mpi.h"

#if (MITM_ROLE != 2)
#error "Wrong MITM_ROLE! Should be 2"
#endif

#if !defined(MITM_AUTH_RSA)
#error "Must define MITM_AUTH_RSA"
#endif

u8 hmac_key[SHA256_DIGEST_SIZE] = {0x00};
#ifdef MITM_AUTH_RSA
u8 proof_key[MITM_PROOF_RSA_KEY_LEN] =
    "\x30\x82\x04\xA3\x02\x01\x00\x02\x82\x01\x01\x00\x9F\x60\xE7\xB8"
    "\x2F\x85\x21\x99\x4B\x6F\x9C\x4F\xBA\x25\x54\xD3\xBE\xD5\x06\x2D"
    "\xC3\xD7\xD8\x05\x05\x27\xD5\xF7\xBC\x37\x6C\x92\xCA\x08\xAA\x5B"
    "\x5D\xFF\x23\x29\x17\x83\x92\x56\x6A\x7A\x74\x20\x2D\x2C\xB0\xF1"
    "\x77\x1D\x6A\x17\x85\x73\xF3\xDF\xE6\x21\x4D\x9F\xE0\x86\xEA\x7D"
    "\x5D\x29\x6E\xF6\xA3\x19\xC8\x60\xD7\x9F\xFD\x25\xD4\x05\xAC\x22"
    "\xB2\xBA\xE6\x68\xFC\x59\x34\xC2\xF4\x8D\xEA\x66\x27\x8E\x4D\x3B"
    "\x33\x58\xD1\xD5\x99\x90\x13\xAF\xC1\xC6\x22\xA7\x33\xB3\x05\xB9"
    "\x3E\xA0\x67\x73\xAA\xEC\x75\xD9\x2D\x27\x46\xF5\x5F\x2D\xF2\x45"
    "\xF8\xF4\xE0\x1C\x43\x3E\x57\xDD\x1B\xAB\x13\xB7\x42\xCD\x5F\x57"
    "\x7B\xA5\x5D\x2B\x71\x3D\xC6\xF8\xDE\xD9\x1B\xFE\xA7\x39\x9C\xAF"
    "\xFC\xCE\x4C\x04\x30\xC1\x22\xDA\xB3\xC4\x17\xAB\x94\xA2\xD4\xC8"
    "\x65\x5F\xE5\xE9\x3E\x05\x93\x7D\xA3\x74\x97\x9C\x47\xDF\x54\x4F"
    "\x91\xEE\x7A\x1E\xEB\x21\x34\x8C\x6E\x29\x8C\x8E\x2C\x54\x95\x5C"
    "\xF8\xFD\xAE\x24\x76\x04\x76\x81\xAD\xC5\x10\x00\xB9\xFF\xCB\xED"
    "\xE5\x0C\x06\xD1\xB9\xC4\x79\x58\x65\xC3\x92\x81\x4C\x41\x1C\x4E"
    "\x5E\x47\x9F\x06\x04\x1E\x1C\x1D\xEE\x69\x97\x51\x02\x03\x01\x00"
    "\x01\x02\x82\x01\x01\x00\x89\x97\xFC\x94\xBB\x99\xC0\xF6\xF9\xF4"
    "\x42\x4B\x66\x56\x02\x54\xC7\xE4\x5A\xF0\x39\xAA\x67\x59\x76\x28"
    "\xFD\x05\x62\x5D\xAB\x03\x53\x1E\x86\x0C\x59\x2B\x02\x2C\xE0\x9A"
    "\xFB\x44\x55\xAA\xA0\x04\x83\x5B\x98\xEA\xED\xBD\xDC\x30\xB0\x4A"
    "\xF9\x99\x2B\xB1\x46\xB5\xA6\xFE\x73\x04\x85\xE0\x56\x66\xE1\x4A"
    "\x49\xFE\xA9\x48\xFB\x20\xA4\x59\xBD\x51\x3B\x62\x35\xB7\x1F\x5C"
    "\xD8\x3B\x13\x2C\x4D\xD7\xA1\x80\xAD\xD6\x55\x2E\xF2\x00\xE9\x11"
    "\x44\x9D\xB0\xB9\xA0\x83\x1F\x14\x07\xF5\xF4\x46\x40\xE9\xCF\xFF"
    "\x52\x82\x8B\x03\xE4\xB2\x66\x67\x71\xB6\x26\x21\xCC\x73\xDC\xE4"
    "\x4A\xDB\x6B\x4D\x31\xE5\x73\x06\xE8\x91\x03\x1D\xD7\xDE\x63\xC3"
    "\x43\xFE\x99\xCB\x17\x3F\x91\xE1\xD3\xAD\x07\x96\x0F\x18\x23\x43"
    "\xB3\x62\xDE\xBD\xC9\x27\x04\x7E\x7D\x0F\x64\x61\xDD\x4E\xAC\x05"
    "\xF4\xBC\x3D\x69\x92\x83\x37\xED\xB7\x99\x3F\x18\x40\x1B\x9D\x02"
    "\x7D\x5D\x20\x56\x0E\xA3\x81\xD6\x2E\x87\xDE\xC7\x99\x57\x45\xB2"
    "\xE5\xAC\x4A\xC7\xA8\xB6\x66\x54\xE3\x55\xF0\x6E\x38\xE1\xEE\x05"
    "\x1B\xDC\x5D\xC7\x1F\x36\xAD\x8C\x09\xAE\xC0\xD3\xC1\x0C\x1B\x3B"
    "\xF2\x21\x68\x19\xAE\x01\x02\x81\x81\x00\xD0\x67\x41\xD9\x9D\x83"
    "\x63\xC3\xE1\xA9\x88\x1F\x97\x10\x84\x40\x00\x4F\xAC\x09\x57\x8C"
    "\xB1\x50\x5D\x88\xDD\x29\x31\xAE\x9B\x20\x54\x1A\x37\xE1\x71\x6D"
    "\x7C\x7B\x32\xE4\xEC\xA1\xFC\x54\x63\xDE\xAB\x25\x8B\x59\x46\xE0"
    "\x7C\xCE\xAD\xC3\xFB\xFA\xF3\x8B\xAA\x90\x45\x0C\x1B\xD6\xC5\xBC"
    "\xA9\x3B\x84\x5B\x45\xF6\x92\x38\xBD\x17\x9E\xCD\xE0\x3F\x94\xBB"
    "\x86\x9D\xBD\x1E\xBB\x23\x50\x3E\x25\x1D\x15\x63\x19\xF4\xE5\xC9"
    "\xA7\x05\x3F\x37\xCF\x92\x1E\xF2\xBF\xF1\x29\x20\x79\x65\x6E\xEF"
    "\x05\x83\x89\x49\x66\x6C\x5A\x9D\xE6\x61\x02\x81\x81\x00\xC3\xC7"
    "\x4E\xFA\x50\x6E\x38\x86\xDE\xD0\x53\x47\x12\x30\xD5\x04\x0C\x8A"
    "\xC2\xA8\x60\xA1\xDC\xFA\x93\x20\x78\x45\x35\xA9\x96\x43\x34\xA4"
    "\x8F\x87\x78\x58\xDB\x98\xD1\x36\x33\x16\x81\x4F\x3E\x35\xD4\xC8"
    "\x46\x9D\xA1\x68\x7C\x4E\xF7\x6A\x52\xE4\xB1\xE2\x2A\x9E\x87\xDA"
    "\xC1\x9A\xE3\x41\x25\x01\xB1\x85\x16\x6A\xE7\x4B\xF4\x7B\x30\x3E"
    "\x32\xC7\x10\x82\x75\x48\x6C\x16\x12\x51\x61\xCF\xE4\xB1\xD9\x5D"
    "\x17\xFF\xEB\xBE\x65\xDC\x70\x05\x3B\x63\x9A\xD1\x6E\xF1\xDD\xBB"
    "\xF8\x92\x4B\x71\x67\x82\x29\x6C\x57\xB3\x9A\x73\x76\xF1\x02\x81"
    "\x80\x31\x91\x9D\xD4\x08\xE7\x0B\x7F\xB7\xD8\xFF\x0B\xA4\x7E\xC5"
    "\x36\x03\xDC\xEF\x6A\x79\x6C\x79\x70\x48\x0F\x19\xAB\x86\xA9\xA5"
    "\x34\x17\x4C\xF5\x25\xA6\x39\x08\x76\xB5\x30\x46\x28\x71\x40\x11"
    "\x51\x11\x1C\x28\xFC\xDF\x22\xDE\x0C\xBA\xBF\xF6\xDB\x45\xBA\x5E"
    "\xA3\x5A\x08\xFB\x46\x26\x5A\x2D\x56\x7E\xB0\xC6\xFF\x52\xE0\x33"
    "\xF9\xBE\x47\xF1\xA2\xAD\xD9\xBC\xB7\x20\x18\x83\x22\x6F\x1F\x98"
    "\xEC\x45\xFE\x00\x5A\x83\x9D\x67\x20\x94\x5C\xCD\xFE\x4F\x66\x25"
    "\xC9\x52\xA2\xEA\xBC\xF9\x99\xD8\x91\xE4\xC1\x94\x9F\x09\x1E\xAD"
    "\x81\x02\x81\x80\x7F\xE2\x1C\x03\xC4\x30\x0B\x3A\x86\x26\xFC\x8E"
    "\xEB\x21\xFC\xB3\x15\x62\x3A\x7E\xF4\x08\x27\x29\x82\x9B\x6E\x14"
    "\x7F\x56\x14\x72\x37\xDB\xDA\x69\x7A\x42\x48\xC7\x4C\xB9\xA3\xAB"
    "\x6A\xB2\x11\x87\xE6\x43\x20\x65\x6C\xFE\xAC\x5C\x84\x9E\xEE\x20"
    "\xB6\xD5\x6E\x53\x79\x98\x7A\x68\xAB\x53\x6D\x51\xEA\xDC\x6D\x65"
    "\x4D\x4A\xBF\x1B\x0C\xCB\x44\x2D\xE5\xE9\xE1\xA4\x79\xFD\xFC\xDF"
    "\x2E\x0E\x37\x6B\xB8\xF9\x67\x68\xE3\x5B\xCE\x7B\xAC\xAC\xAE\x3B"
    "\x84\xF0\x93\x10\xE8\x6F\x15\x92\xB2\x37\x14\x8E\xE0\x72\x05\xE3"
    "\xAA\xDB\x0B\x71\x02\x81\x80\x41\x8D\x1A\xE6\xE2\x04\xF9\x7D\x60"
    "\xC4\x1E\x10\x03\x44\x25\xD5\x7B\x5D\xF1\xAC\xB0\x6A\xD3\x42\xE1"
    "\x9A\xC2\xB8\x26\xB8\xB2\xA9\x32\x9C\x26\x3C\x6B\x87\x62\x1E\x33"
    "\xE5\xA2\x37\x1A\xD9\x29\x8A\x0B\xF2\x4E\x02\x42\x81\x37\x21\x8A"
    "\x75\x12\xD7\x54\x45\xF3\x30\xDB\x3B\xC7\x0F\x0B\xD1\x4B\x00\xED"
    "\xB0\x4B\xD4\x6D\xDB\xE4\x1D\xC9\x2B\xB9\xD6\x61\x40\x74\x4A\x8D"
    "\x50\x60\xCB\x99\xD4\x34\xEA\x8F\xB5\xD2\xFF\xCC\xD3\x5C\x3B\x4A"
    "\x33\xA9\x1E\x88\x9F\x92\x69\x45\x3A\xF8\x4D\x53\x4C\x78\x95\x13"
    "\x51\x19\xB3\x24\x15\x9E\x14";
#else
u8 proof_key[SHA256_DIGEST_SIZE] = {0x01};
#endif /* MITM_AUTH_RSA */

// store bytes received for every connected ports
u64 dev_rx_bytes[NET_MONITOR_MAX_NUM] = {0x00};

#ifdef MITM_DOS_PROTECTION
/* Network monitor callback */
void net_monitor_cb(struct timer_list *timer) {
  int err;
  int i = 0;
  struct mitm *mitm = from_timer(mitm, timer, net_monitor_timer);
  struct slave *slave = mitm_slave(mitm);
  struct net_device *br_dev = slave->dev;
  struct net_device *br_port_dev;
  struct list_head *iter;
  struct rtnl_link_stats64 stats;
  u64 rx_bps;

  err = mod_timer(timer, jiffies + msecs_to_jiffies(NET_MONITOR_DELAY));
  if (err) {
    netdev_err(mitm->dev, "Failed to set timer\n");
    return;
  }

  // retrieve traffic stats
  netdev_for_each_lower_dev(br_dev, br_port_dev, iter) {
    dev_get_stats(br_port_dev, &stats);

    rx_bps = (stats.rx_bytes - dev_rx_bytes[i]) * 8 * 1000 / NET_MONITOR_DELAY;
    netdev_info(
        mitm->dev, "throughput (%s): %llu bps\n", br_port_dev->name, rx_bps);
    // TODO: if `rx_bps` is greater than the expected throughput, the
    //  authenticator will send a time-lock puzzle

    dev_rx_bytes[i++] = stats.rx_bytes;
  }
}
#endif /* MITM_DOS_PROTECTION */

/* Taken out of net/bridge/br_forward.c */
static int mitm_deliver_proof(
    struct mitm *mitm, struct net_device *to, struct sk_buff *skbn,
    const u8 *data, unsigned int len) {
  int ret;
  struct sk_buff *skb;
  struct ethhdr *eth;
#ifndef MITM_AUTH_RSA
  struct crypto_shash *tfm;
  struct shash_desc *desc;
  struct proofhdr *proof;
#endif /* MITM_AUTH_RSA */
  struct slave *slave = mitm_slave(mitm);
  struct net_device *slave_dev = slave->dev;

  // clone a buffer
  //    netdev_info(mitm->dev, "before cloning the sk_buff\n");
  skb = skb_clone(skbn, GFP_ATOMIC);
  //    netdev_info(mitm->dev, "after cloning the sk_buff\n");
  if (!skb) return -ENOMEM;
  skb->dev = to;
  skb->pkt_type = PACKET_OUTGOING;
#ifndef MITM_AUTH_RSA
  proof = proof_hdr(skb);
#endif /* MITM_AUTH_RSA */

  //    netdev_info(mitm->dev, "setup the hardware header\n");
  eth = skb_push(skb, ETH_HLEN);
  eth->h_proto = htons(ETH_P_MITM_AUTH);
  eth_broadcast_addr(eth->h_dest);  // broadcast destination
  //    eth_random_addr(eth->h_source); // random source address
  memcpy(
      eth->h_source, slave_dev->dev_addr,
      ETH_ALEN);  // use the MAC address of the slave device
  //    ret = dev_hard_header(skb, slave_dev, ETH_P_MITM_AUTH, slave_dev->broadcast, NULL, skb->len);
  //    if (ret < 0) {
  //        netdev_err(mitm->dev, "dev_hard_header failed: err %d\n", ret);
  //        goto failed;
  //    }
  // !!!: this is important, because we will use `skb->mac_header` later
  skb_reset_mac_header(skb);

#ifndef MITM_AUTH_RSA
  // calculate new hmac
  tfm = mitm->proof_shash;
  //    netdev_info(mitm->dev, "before allocating shash_desc for hmac-sha256: %zu bytes\n", sizeof(struct shash_desc) + crypto_shash_descsize(tfm));
  desc = kzalloc(
      sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
  if (!desc) {
    // error: no memory
    netdev_err(mitm->dev, "cannot allocate shash_desc\n");
    ret = -ENOMEM;
    goto failed;
  }
  desc->tfm = tfm;

  //    netdev_info(mitm->dev, "calculate hmac for the proof packet\n");
  //    netdev_info(mitm->dev, "before crypto_shash_digest for hmac-sha256: %u bytes\n", len);
  ret = crypto_shash_digest(desc, data, len, proof->proof_hmac);
  //    netdev_info(mitm->dev, "after crypto_shash_digest\n");
  kfree(desc);
  //    netdev_info(mitm->dev, "after freeing shash_desc\n");
  if (ret < 0) {
    // error
    netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
    goto failed;
  }
#endif /* MITM_AUTH_RSA */

//      netdev_info(
//              mitm->dev,
//              "skb len=%u data_len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n",
//              skb->len, skb->data_len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);
//      netdev_info(
//              mitm->dev,
//              "dump output data, %u bytes\n",
//              skb->tail - skb->mac_header);
//      print_hex_dump(
//              KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
//              skb_mac_header(skb), skb->tail - skb->mac_header, true);

  // send packet out
  //    netdev_info(mitm->dev, "send the proof packet to (%p)\n", to);
  ret = dev_queue_xmit(skb);
  netdev_info(mitm->dev, "dev_queue_xmit() returns %d\n", ret);

  return 0;

failed:
  kfree_skb(skb);
  return ret;
}

enum mitm_handler_result
mitm_from_slave(struct mitm *mitm, struct sk_buff *skb) {
  uint16_t protocol = ntohs(vlan_get_protocol(skb));
  uint8_t *header = skb_mac_header(skb);
  struct slave *slave = mitm_slave(mitm);
  struct net_device *br_dev = slave->dev;
  struct net_device *br_port_dev;
  struct list_head *iter;
  // `skb->dev` is not the source device, because `br_pass_frame_up` has already
  // changed this field to the bridge device
  struct net_device *src_dev;

  // If IPv4...
  if (protocol == ETH_P_IP) {
    // Find IP header.
    struct iphdr *iph = ip_hdr(skb);
    struct ethhdr *eth = (struct ethhdr *) header;
    bool is_broadcast = is_broadcast_ether_addr(eth->h_dest);
    // UDP ...
    if (iph->protocol == IPPROTO_UDP && is_broadcast) {
      int ret;
      struct sk_buff *skbn;  // new skb
      struct proofhdr *proof;
      int hlen;
      int tlen;
      unsigned int plen = proof_hdr_len();

#ifdef MITM_AUTH_RSA
      struct crypto_akcipher *sig_tfm;
      struct akcipher_request *sig_req;
      unsigned int proof_key_size;
      struct scatterlist src, dst;
      struct crypto_wait wait;
#endif                           /* MITM_AUTH_RSA */
      struct crypto_shash *tfm;  // for hash and hmac
      struct shash_desc *desc;
      u8 data[SHA256_DIGEST_SIZE];
      struct udphdr *udph = udp_hdr(skb);
      uint8_t *udp_payload_end = (uint8_t *) udph + ntohs(udph->len);
      unsigned int tail_data_len = skb_tail_pointer(skb) - udp_payload_end;

      netdev_info(mitm->dev, "Observe incoming broadcast UDP packets\n");
      //		    netdev_info(mitm->dev, "  Source:\n");
      //		    netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_source);
      //		    netdev_info(mitm->dev, "    IP: %pI4\n", &iph->saddr);
      //		    netdev_info(mitm->dev, "  Dest:\n");
      //		    netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_dest);
      //		    netdev_info(mitm->dev, "    IP: %pI4\n", &iph->daddr);

      //		    netdev_info(
      //		            mitm->dev,
      //		            "skb len=%u data_len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n",
      //		            skb->len, skb->data_len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);
      //            netdev_info(
      //                    mitm->dev,
      //                    "dump input data (i.e., the whole packet), %u bytes\n",
      //                    skb->tail - skb->mac_header);
      //            print_hex_dump(
      //                    KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
      //                    skb_mac_header(skb), skb->tail - skb->mac_header, true);

      //            netdev_info(mitm->dev, "tail pointer=%px\n", skb_tail_pointer(skb));
      //            netdev_info(mitm->dev, "udp payload end=%px, udp len=%hu\n", udp_payload_end, ntohs(udph->len));
      //            netdev_info(mitm->dev, "tail data len=%u\n", tail_data_len);
      if (tail_data_len != ARRAY_SIZE(data)) {
        // no additional data
        netdev_info(mitm->dev, "normal packet, no appended data\n");
        return MITM_FORWARD;
      }

      // remove the appended MAC
      skb->tail -= ARRAY_SIZE(data);
      skb->len -= ARRAY_SIZE(data);

      // calculate and verify MAC
      /* From `hmac_sha256` at net/bluetooth/amp.c */
      tfm = mitm->hmac_shash;
      //			netdev_info(mitm->dev, "before allocating shash_desc for hmac-sha256: %zu bytes\n", sizeof(struct shash_desc) + crypto_shash_descsize(tfm));
      desc = kzalloc(
          sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
      if (!desc) {
        // error: no memory
        netdev_err(mitm->dev, "cannot allocate shash_desc\n");
        return MITM_DROP;
      }
      desc->tfm = tfm;

      //            netdev_info(mitm->dev, "before crypto_shash_digest for hmac-sha256: %u bytes\n", skb->tail - skb->mac_header);
      ret = crypto_shash_digest(
          desc, skb_mac_header(skb), skb->tail - skb->mac_header, data);
      //            netdev_info(mitm->dev, "after crypto_shash_digest\n");
      kfree(desc);
      //            netdev_info(mitm->dev, "after freeing shash_desc\n");
      if (ret < 0) {
        // error
        netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
        return MITM_DROP;
      }

      // verify the digest
      //            netdev_info(mitm->dev, "before crypto_memneq: 32 bytes\n");
      ret = crypto_memneq(data, skb_tail_pointer(skb), ARRAY_SIZE(data));
      if (ret) {
        // non-equal
        netdev_alert(mitm->dev, "wrong MAC\n");
        // wrong MAC
        return MITM_DROP;
      }
      netdev_info(mitm->dev, "correct MAC\n");

      // find the source device according to the MAC address
      //            netdev_info(mitm->dev, "before br_fdb_find_port\n");
      rtnl_lock();
      src_dev = br_fdb_find_port(br_dev, eth->h_source, 0);
      rtnl_unlock();
      //			netdev_info(mitm->dev, "after br_fdb_find_port\n");

      // create `skbn` as a template
      hlen = LL_RESERVED_SPACE(src_dev);
      tlen = src_dev->needed_tailroom;
      //			netdev_info(mitm->dev, "before alloc_skb: %u bytes\n", plen + hlen + tlen);
      skbn = alloc_skb(plen + hlen + tlen, GFP_ATOMIC);
      if (!skbn) {
        netdev_err(mitm->dev, "cannot allocate sk_buff for proof packets\n");
        // cannot allocate memory for proof packets
        return MITM_DROP;
      }
      //            netdev_info(mitm->dev, "after alloc_skb\n");

      skb_reserve(skbn, hlen);
      skb_reset_network_header(skbn);  // now points to the proof header
      proof = skb_put(skbn, plen);
      skbn->protocol = htons(ETH_P_MITM_AUTH);

      // calculate the hash, fill it into `proof->pkt_hash`
      tfm = mitm->hash_shash;
      //			netdev_info(mitm->dev, "before allocating shash_desc for sha256: %zu bytes\n", sizeof(struct shash_desc) + crypto_shash_descsize(tfm));
      desc = kzalloc(
          sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
      if (!desc) {
        // error: no memory
        kfree_skb(skbn);
        netdev_err(mitm->dev, "cannot allocate shash_desc\n");
        // cannot generate hash
        return MITM_DROP;
      }
      desc->tfm = tfm;

      //            netdev_info(mitm->dev, "before crypto_shash_digest: %u bytes\n", skb->tail - skb->mac_header);
//      ret = crypto_shash_digest(
//          desc, skb_mac_header(skb), skb->tail - skb->mac_header,
//          proof->pkt_hash);
      ret = crypto_shash_digest(
          desc, skb_mac_header(skb), skb->tail - skb->mac_header,
          proof->pkt_hash);
      //            netdev_info(mitm->dev, "after crypto_shash_digest\n");
      kfree(desc);
      //            netdev_info(mitm->dev, "after freeing shash_desc\n");
      if (ret < 0) {
        // error
        kfree_skb(skbn);
        netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
        // cannot generate hash
        return MITM_DROP;
      }

#ifdef MITM_AUTH_RSA
      // generate digital signatures
      sig_tfm = mitm->proof_akcipher;
      sig_req = mitm->proof_req;
      proof_key_size = crypto_akcipher_maxsize(sig_tfm);

      if (proof_key_size != PROOF_SIG_SIZE) {
        // error: wrong key size
        kfree_skb(skbn);
        netdev_err(
            mitm->dev, "crypto_akcipher_maxsize failed: wrong key size %u\n",
            proof_key_size);

        // cannot generate proof
        return MITM_DROP;
      }

      // sign
      sg_init_one(&src, proof->pkt_hash, sizeof(proof->pkt_hash));
      sg_init_one(&dst, proof->proof_sig, sizeof(proof->proof_sig));
      akcipher_request_set_crypt(
          sig_req, &src, &dst, sizeof(proof->pkt_hash),
          sizeof(proof->proof_sig));

      crypto_init_wait(&wait);
      akcipher_request_set_callback(
          sig_req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
      netdev_info(mitm->dev, "before crypto_akcipher_sign\n");
      ret = crypto_akcipher_sign(sig_req);
      netdev_info(mitm->dev, "crypto_akcipher_sign ret: %d\n", ret);
      ret = crypto_wait_req(ret, &wait);
      if (ret < 0) {
        // error: cannot sign
        kfree_skb(skbn);
        netdev_err(mitm->dev, "crypto_akcipher_sign failed: err %d\n", ret);
        // cannot generate proof
        return MITM_DROP;
      }
      netdev_info(mitm->dev, "crypto_akcipher_sign done\n");

      // copy results back
//      memcpy(proof->pkt_hash, mitm->xbuf[0], sizeof(proof->pkt_hash));
//      memcpy(proof->proof_sig, mitm->xbuf[1], sizeof(proof->proof_sig));
#endif /* MITM_AUTH_RSA */

      // iterate over all slave devices of the bridge device
      //			netdev_info(mitm->dev, "iterating over all ports to send proof packets\n");
      netdev_for_each_lower_dev(br_dev, br_port_dev, iter) {
        if (br_port_dev == src_dev) continue;

        //                netdev_info(mitm->dev, "other br_port_dev=%p\n", br_port_dev);

        // `skbn` will be cloned in the function
        ret = mitm_deliver_proof(
            mitm, br_port_dev, skbn, skb_mac_header(skb),
            skb->tail - skb->mac_header);
        if (ret < 0) {
          netdev_err(
              mitm->dev, "cannot deliver proof packet to br_port_dev=%p\n",
              br_port_dev);
          break;
        }
      }
      //            netdev_info(mitm->dev, "after iterating over ports\n");

      // free the original `skbn`
      kfree_skb(skbn);

      return MITM_FORWARD;
    }
  }

  return MITM_FORWARD;
}

enum mitm_handler_result
mitm_from_master(struct mitm *mitm, struct sk_buff *skb) {
  return forward(mitm, skb);
}

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>

static unsigned int prev_skb_len = 0;

// The following two functions are hooked to `NF_BR_PRE_ROUTING` with different
// priority. Therefore, they will be called sequentially.
static unsigned int br_pre_routing_first_hookfn(
    void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct mitm *mitm = (struct mitm *) priv;

  netdev_info(mitm->dev, "NF_BR_PRE_ROUTING first\n");
  netdev_info(
      mitm->dev,
      "skb=%px: len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n", skb,
      skb->len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);

  prev_skb_len = skb->len;

  return NF_ACCEPT;
}

static unsigned int br_pre_routing_last_hookfn(
    void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct mitm *mitm = (struct mitm *) priv;

  netdev_info(mitm->dev, "NF_BR_PRE_ROUTING last\n");
  netdev_info(
      mitm->dev,
      "skb=%px: len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n", skb,
      skb->len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);

  if (skb->len == prev_skb_len) return NF_ACCEPT;

  // adjust inconsistent length
  netdev_info(mitm->dev, "adjust skb->len\n");
  skb->len = prev_skb_len;
  skb_set_tail_pointer(skb, prev_skb_len);

  return NF_ACCEPT;
}

static unsigned int br_local_in_hookfn(
    void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
  struct mitm *mitm = (struct mitm *) priv;

  netdev_info(mitm->dev, "NF_BR_LOCAL_IN\n");
  netdev_info(
      mitm->dev,
      "skb=%px: len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n", skb,
      skb->len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);
  return NF_ACCEPT;
}

struct nf_hook_ops br_debug_nf_ops[NUM_BR_NF_HOOKS] = {
    {
        .hook = br_pre_routing_first_hookfn,
        .pf = NFPROTO_BRIDGE,
        .hooknum = NF_BR_PRE_ROUTING,
        .priority = NF_BR_PRI_FIRST,
        .priv = NULL,  // will fill later
    },
    {
        .hook = br_pre_routing_last_hookfn,
        .pf = NFPROTO_BRIDGE,
        .hooknum = NF_BR_PRE_ROUTING,
        .priority = NF_BR_PRI_LAST,
        .priv = NULL,  // will fill later
    },
    {
        .hook = br_local_in_hookfn,
        .pf = NFPROTO_BRIDGE,
        .hooknum = NF_BR_LOCAL_IN,
        .priority = NF_BR_PRI_FIRST,
    },
};
#endif
