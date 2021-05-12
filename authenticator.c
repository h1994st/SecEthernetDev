//
// Created by h1994st on 4/15/21.
//

#include "authenticator.h"
#include "proof.h"

#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/udp.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#if (MITM_ROLE != 2)
#error "Wrong MITM_ROLE! Should be 2"
#endif

u8 hmac_key[SHA256_DIGEST_SIZE] = { 0x00 };
u8 proof_key[SHA256_DIGEST_SIZE] = { 0x01 };

/* Taken out of net/bridge/br_forward.c */
static int mitm_deliver_proof(struct mitm *mitm, struct net_device *to, struct sk_buff *skbn,
                              const u8 *data, unsigned int len)
{
    int ret;
    struct sk_buff *skb;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct ethhdr *eth;
    struct proofhdr *proof;
    struct slave *slave = mitm_slave(mitm);
    struct net_device *slave_dev = slave->dev;

    // clone a buffer
    netdev_info(mitm->dev, "clone the sk_buff\n");
    skb = skb_clone(skbn, GFP_ATOMIC);
    if (!skb)
        return -ENOMEM;
    proof = proof_hdr(skb);
    skb->dev = to;
    skb->pkt_type = PACKET_OUTGOING;

    netdev_info(mitm->dev, "setup the hardware header\n");
    eth = skb_push(skb, ETH_HLEN);
    eth->h_proto = htons(ETH_P_MITM_AUTH);
    eth_broadcast_addr(eth->h_dest); // broadcast destination
//    eth_random_addr(eth->h_source); // random source address
    memcpy(eth->h_source, slave_dev->dev_addr, ETH_ALEN); // use the MAC address of the slave device
//    ret = dev_hard_header(skb, slave_dev, ETH_P_MITM_AUTH, slave_dev->broadcast, NULL, skb->len);
//    if (ret < 0) {
//        netdev_err(mitm->dev, "dev_hard_header failed: err %d\n", ret);
//        goto failed;
//    }
    // !!!: this is important, because we will use `skb->mac_header` later
    skb_reset_mac_header(skb);

    // calculate new hmac
    tfm = mitm->proof_shash;
    desc = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        // error: no memory
        netdev_err(mitm->dev, "cannot allocate shash_desc\n");
        ret = -ENOMEM;
        goto failed;
    }
    desc->tfm = tfm;

    netdev_info(mitm->dev, "calculate hmac for the proof packet\n");
    ret = crypto_shash_digest(desc, data, len, proof->proof_hmac);
    kfree(desc);
    if (ret < 0) {
        // error
        netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
        goto failed;
    }

//    netdev_info(
//            mitm->dev,
//            "skb len=%u data_len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n",
//            skb->len, skb->data_len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);
//    netdev_info(
//            mitm->dev,
//            "dump output data, %u bytes\n",
//            skb->tail - skb->mac_header);
//    print_hex_dump(
//            KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
//            skb_mac_header(skb), skb->tail - skb->mac_header, true);

    // send packet out
    netdev_info(mitm->dev, "send the proof packet to (%p)\n", to);
	ret = dev_queue_xmit(skb);
	netdev_info(mitm->dev, "dev_queue_xmit() returns %d\n", ret);

    return 0;

failed:
    kfree_skb(skb);
    return ret;
}

enum mitm_handler_result mitm_from_slave(struct mitm *mitm, struct sk_buff *skb)
{
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
		struct ethhdr *eth = (struct ethhdr *)header;
//		is_broadcast_ether_addr(eth->h_dest);
		// UDP ...
		if (iph->protocol == IPPROTO_UDP) {
            int ret;
            struct sk_buff *skbn; // new skb
            struct proofhdr *proof;
            int hlen;
            int tlen;
            unsigned int plen = proof_hdr_len();

            struct crypto_shash *tfm;
            struct shash_desc *desc;
		    u8 data[SHA256_DIGEST_SIZE];
			struct udphdr *udph = udp_hdr(skb);
			uint8_t *udp_payload_end = (uint8_t *)udph + ntohs(udph->len);
			unsigned int tail_data_len = skb_tail_pointer(skb) - udp_payload_end;

//		    netdev_info(mitm->dev, "Observe incoming broadcast UDP packets\n");
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

            netdev_info(mitm->dev, "tail pointer=%px\n", skb_tail_pointer(skb));
            netdev_info(mitm->dev, "udp payload end=%px, udp len=%hu\n", udp_payload_end, ntohs(udph->len));
            netdev_info(mitm->dev, "tail data len=%u\n", tail_data_len);
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
            desc = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
            if (!desc) {
                // error: no memory
                netdev_err(mitm->dev, "cannot allocate shash_desc\n");
                return MITM_FORWARD;
            }
            desc->tfm = tfm;

            ret = crypto_shash_digest(desc, skb_mac_header(skb), skb->tail - skb->mac_header, data);
            kfree(desc);
            if (ret < 0) {
                // error
                netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
                return MITM_FORWARD;
            }

            // verify the digest
            ret = crypto_memneq(data, skb_tail_pointer(skb), ARRAY_SIZE(data));
            if (ret) {
                // non-equal
                netdev_alert(mitm->dev, "wrong MAC\n");
                return MITM_FORWARD;
            }
            netdev_info(mitm->dev, "correct MAC\n");

            // find the source device according to the MAC address
			rtnl_lock();
			src_dev = br_fdb_find_port(br_dev, eth->h_source, 0);
			rtnl_unlock();

			// create `skbn` as a template
			hlen = LL_RESERVED_SPACE(src_dev);
			tlen = src_dev->needed_tailroom;
			skbn = alloc_skb(plen + hlen + tlen, GFP_ATOMIC);
            if (!skbn) {
                netdev_err(mitm->dev, "cannot allocate sk_buff for proof packets\n");
                return MITM_FORWARD;
            }

			skb_reserve(skbn, hlen);
            skb_reset_network_header(skbn); // now points to the proof header
            proof = skb_put(skbn, plen);
            skbn->protocol = htons(ETH_P_MITM_AUTH);

			// calculate the hash, fill it into `proof->pkt_hash`
			tfm = mitm->hash_shash;
            desc = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
            if (!desc) {
                // error: no memory
                kfree_skb(skbn);
                netdev_err(mitm->dev, "cannot allocate shash_desc\n");
                return MITM_FORWARD;
            }
            desc->tfm = tfm;

            ret = crypto_shash_digest(desc, skb_mac_header(skb), skb->tail - skb->mac_header, proof->pkt_hash);
            kfree(desc);
            if (ret < 0) {
                // error
                kfree_skb(skbn);
                netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
                return MITM_FORWARD;
            }

			// iterate over all slave devices of the bridge device
            netdev_for_each_lower_dev(br_dev, br_port_dev, iter) {
                if (br_port_dev == src_dev)
                    continue;

                netdev_info(mitm->dev, "other br_port_dev=%p\n", br_port_dev);

                // `skbn` will be cloned in the function
                ret = mitm_deliver_proof(mitm, br_port_dev, skbn,
                                         skb_mac_header(skb), skb->tail - skb->mac_header);
                if (ret < 0) {
                    netdev_err(mitm->dev, "cannot deliver proof packet to br_port_dev=%p\n", br_port_dev);
                    break;
                }
            }

            // free the original `skbn`
            kfree_skb(skbn);

            return MITM_FORWARD;
		}
	}

	return MITM_FORWARD;
}

enum mitm_handler_result mitm_from_master(struct mitm *mitm, struct sk_buff *skb)
{
	return forward(mitm, skb);
}
