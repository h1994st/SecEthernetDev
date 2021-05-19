//
// Created by h1994st on 4/15/21.
//

#include "sender.h"

#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/udp.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#if (MITM_ROLE != 0)
#error "Wrong MITM_ROLE! Should be 0"
#endif

u8 hmac_key[SHA256_DIGEST_SIZE] = { 0x00 };

enum mitm_handler_result mitm_from_slave(struct mitm *mitm, struct sk_buff *skb)
{
	return forward(mitm, skb);
}

enum mitm_handler_result mitm_from_master(struct mitm *mitm, struct sk_buff *skb)
{
    uint16_t protocol = ntohs(vlan_get_protocol(skb));
    uint8_t *header = skb_mac_header(skb);

    // If IPv4...
    if (protocol == ETH_P_IP) {
        // Find IP header.
        struct iphdr *iph = ip_hdr(skb);
        struct ethhdr *eth = (struct ethhdr *) header;
		bool is_broadcast = is_broadcast_ether_addr(eth->h_dest);

        // UDP ...
        if (iph->protocol == IPPROTO_UDP && is_broadcast) {
            int ret;
            struct crypto_shash *tfm;
            struct shash_desc *desc;
            u8 data[SHA256_DIGEST_SIZE];
//            struct udphdr *udph = udp_hdr(skb);

//            uint16_t sport = ntohs(udph->source);
//            uint16_t dport = ntohs(udph->dest);

            netdev_info(mitm->dev, "Observe outgoing broadcast UDP packets\n");
//            netdev_info(mitm->dev, "  Source:\n");
//            netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_source);
//            netdev_info(mitm->dev, "    IP: %pI4\n", &iph->saddr);
//            netdev_info(mitm->dev, "    Port: %hu\n", sport);
//            netdev_info(mitm->dev, "  Dest:\n");
//            netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_dest);
//            netdev_info(mitm->dev, "    IP: %pI4\n", &iph->daddr);
//            netdev_info(mitm->dev, "    Port: %hu\n", dport);

//            netdev_info(
//                    mitm->dev,
//                    "skb len=%u data_len=%u headroom=%u head=%px data=%px, tail=%u, end=%u\n",
//                    skb->len, skb->data_len, skb_headroom(skb), skb->head, skb->data, skb->tail, skb->end);

            /* From `hmac_sha256` at net/bluetooth/amp.c */
            tfm = mitm->hmac_shash;
//            netdev_info(mitm->dev, "before allocating shash_desc for hmac-sha256: %zu bytes\n", sizeof(struct shash_desc) + crypto_shash_descsize(tfm));
            desc = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
            if (!desc) {
                // error: no memory
                netdev_err(mitm->dev, "cannot allocate shash_desc\n");
                return MITM_FORWARD;
            }
            desc->tfm = tfm;

//            netdev_info(mitm->dev, "before crypto_shash_digest for hmac-sha256: %u bytes\n", skb->tail - skb->mac_header);
            ret = crypto_shash_digest(desc, skb_mac_header(skb), skb->tail - skb_headroom(skb), data);
//            netdev_info(mitm->dev, "after crypto_shash_digest\n");
            kfree(desc);
//            netdev_info(mitm->dev, "after freeing shash_desc\n");
            if (ret < 0) {
                // error
                netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
                return MITM_FORWARD;
            }

            // attach MAC to the end of the buffer
//            netdev_info(mitm->dev, "before skb_put_data: 32 bytes\n");
            skb_put_data(skb, data, ARRAY_SIZE(data));
            netdev_info(mitm->dev, "after skb_put_data\n");

//            netdev_info(
//                    mitm->dev,
//                    "dump input data (i.e., the whole packet), %u bytes\n",
//                    skb->tail - skb->mac_header);
//            print_hex_dump(
//                    KERN_INFO, "", DUMP_PREFIX_NONE, 16, 1,
//                    skb_mac_header(skb), skb->tail - skb->mac_header, true);

            return MITM_FORWARD;
        }
    }

	return MITM_FORWARD;
}
