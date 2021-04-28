//
// Created by h1994st on 4/15/21.
//

#include "receiver.h"
#include "proof.h"

#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/udp.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#if (MITM_ROLE != 1)
#error "Wrong MITM_ROLE! Should be 1"
#endif

u8 hmac_key[SHA256_DIGEST_SIZE] = { 0x01 };

enum mitm_handler_result handle_proof_packets(struct mitm *mitm, struct sk_buff *skb)
{
    struct proofhdr *proof = proof_hdr(skb);

    netdev_info(mitm->dev, "observe proof packets!\n");

    return MITM_CONSUMED;
}

enum mitm_handler_result mitm_from_slave(struct mitm *mitm, struct sk_buff *skb)
{
    uint16_t protocol = ntohs(vlan_get_protocol(skb));
    uint8_t *header = skb_mac_header(skb);

    // If IPv4...
    if (protocol == ETH_P_IP) {
        // Find IP header.
        struct iphdr *iph = ip_hdr(skb);
        struct ethhdr *eth = (struct ethhdr *) header;
//		is_broadcast_ether_addr(eth->h_dest);
        // UDP ...
        if (iph->protocol == IPPROTO_UDP) {
//            int ret;
//            struct crypto_shash *tfm;
//            struct shash_desc *desc;
            u8 data[SHA256_DIGEST_SIZE] __maybe_unused;
            struct udphdr *udph = udp_hdr(skb);
            uint8_t *udp_payload_end = (uint8_t *) udph + ntohs(udph->len);
            unsigned int tail_data_len = skb_tail_pointer(skb) - udp_payload_end;

            uint16_t sport = ntohs(udph->source);
            uint16_t dport = ntohs(udph->dest);

            netdev_info(mitm->dev, "Observe incoming broadcast UDP packets\n");
            netdev_info(mitm->dev, "  Source:\n");
            netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_source);
            netdev_info(mitm->dev, "    IP: %pI4\n", &iph->saddr);
            netdev_info(mitm->dev, "    Port: %hu\n", sport);
            netdev_info(mitm->dev, "  Dest:\n");
            netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_dest);
            netdev_info(mitm->dev, "    IP: %pI4\n", &iph->daddr);
            netdev_info(mitm->dev, "    Port: %hu\n", dport);

            netdev_info(
                    mitm->dev,
                    "skb len=%u data_len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n",
                    skb->len, skb->data_len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);

            netdev_info(
                    mitm->dev,
                    "dump input data (i.e., the whole packet), %u bytes\n",
                    skb->tail - skb->mac_header);
            print_hex_dump(
                    KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
                    skb_mac_header(skb), skb->tail - skb->mac_header, true);

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

            // TODO: calculate the hash

            // TODO: store the packet in a hash table

            return MITM_FORWARD;
        }
    } else if (protocol == ETH_P_MITM_AUTH) {
        return handle_proof_packets(mitm, skb);
    }

    return MITM_FORWARD;
}

enum mitm_handler_result mitm_from_master(struct mitm *mitm, struct sk_buff *skb)
{
	return MITM_FORWARD;
}
