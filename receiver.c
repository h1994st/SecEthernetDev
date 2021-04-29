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
#include <linux/rhashtable.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#if (MITM_ROLE != 1)
#error "Wrong MITM_ROLE! Should be 1"
#endif

static u8 data[SHA256_DIGEST_SIZE] __maybe_unused = { 0x00 }; // a temporary place to store hash/MAC data
u8 hmac_key[SHA256_DIGEST_SIZE] = { 0x01 };

static const struct rhashtable_params mitm_skb_rht_params = {
        .head_offset = offsetof(struct mitm_skb_entry, rhnode),
        .key_offset = offsetof(struct mitm_skb_entry, skb_hash),
        .key_len = SHA256_DIGEST_SIZE,
        .automatic_shrinking = true
};
static struct rhashtable mitm_skb_hash_tbl;

int mitm_skb_rht_init(void)
{
    return rhashtable_init(&mitm_skb_hash_tbl, &mitm_skb_rht_params);
}

void mitm_skb_rht_fini(void)
{
    rhashtable_destroy(&mitm_skb_hash_tbl);
}

static struct mitm_skb_entry *mitm_skb_rht_get(const void *skb_hash)
{
    struct mitm_skb_entry *ent;

    rcu_read_lock();
    ent = rhashtable_lookup(&mitm_skb_hash_tbl, skb_hash, mitm_skb_rht_params);
    rcu_read_unlock();

    return ent;
}

enum mitm_handler_result handle_proof_packets(struct mitm *mitm, struct sk_buff *skb)
{
    int ret;
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    struct mitm_skb_entry *skb_entry;
    struct sk_buff *old_skb;
    struct proofhdr *proof = proof_hdr(skb);

    netdev_info(mitm->dev, "observe proof packets!\n");

    skb_entry = mitm_skb_rht_get(proof->pkt_hash);
    if (!skb_entry) {
        netdev_err(mitm->dev, "drop the proof packet, as no corresponding packet exists!\n");
        return MITM_DROP;
    }
    old_skb = skb_entry->skb;

    // calculate and verify MAC
    tfm = mitm->hmac_shash;
    desc = kzalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc) {
        // error: no memory
        netdev_err(mitm->dev, "cannot allocate shash_desc\n");
        return MITM_DROP;
    }
    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, skb_mac_header(old_skb), old_skb->tail - old_skb->mac_header, data);
    kfree(desc);
    if (ret < 0) {
        // error
        netdev_err(mitm->dev, "crypto_shash_digest failed: err %d\n", ret);
        return MITM_DROP;
    }

    // verify the digest
    ret = crypto_memneq(data, proof->proof_hmac, ARRAY_SIZE(data));
    if (ret) {
        // non-equal
        netdev_alert(mitm->dev, "wrong MAC\n");
        return MITM_DROP;
    }
    netdev_info(mitm->dev, "correct MAC\n");

    // remove the entry
    netdev_info(mitm->dev, "remove skb_entry=%p from the hash table\n", skb_entry);
    rhashtable_remove_fast(&mitm_skb_hash_tbl, &skb_entry->rhnode, mitm_skb_rht_params);
    kfree(skb_entry);

    // delivery the packet
    old_skb->dev = mitm->dev; // Associate packet with master
    netdev_info(mitm->dev, "remove skb_entry=%p from the hash table\n", skb_entry);
    netif_receive_skb(old_skb);

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
            int ret;
            struct crypto_shash *tfm;
            struct shash_desc *desc;
            struct mitm_skb_entry *skb_entry;
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

            // calculate the hash
			tfm = mitm->hash_shash;
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

            // TODO: store the packet in a hash table
            skb_entry = mitm_skb_rht_get(data);
            if (skb_entry) {
                // duplicate packets?
                netdev_info(mitm->dev, "the packet has already existed\n");
                return MITM_FORWARD;
            }

            skb_entry = kzalloc(sizeof(struct mitm_skb_entry), GFP_ATOMIC);
            if (unlikely(!skb_entry)) {
                // error: no memory
                netdev_err(mitm->dev, "cannot allocate mitm_skb_entry\n");
                return MITM_FORWARD;
            }

            skb_entry->skb = skb;
            memcpy(skb_entry->skb_hash, data, ARRAY_SIZE(data));
            ret = rhashtable_insert_fast(&mitm_skb_hash_tbl, &skb_entry->rhnode, mitm_skb_rht_params);
            if (ret) {
                // error
                kfree(skb_entry);
                netdev_err(mitm->dev, "rhashtable_insert_fast failed: err %d\n", ret);
                return MITM_FORWARD;
            }

            // consumed the packet by default
            // TODO: will the sk_buff be released elsewhere?
            netdev_info(mitm->dev, "stored the packet in the hash table!\n");
            return MITM_CONSUMED;
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
