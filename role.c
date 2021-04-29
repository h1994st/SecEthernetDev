//
// Created by h1994st on 4/15/21.
//

#include "role.h"

#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/udp.h>

// Swap src/dest ethernet addresses
static void eth_swap_addr(struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
	unsigned char tmp[ETH_ALEN];

	memcpy(tmp, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp, ETH_ALEN);
}

enum mitm_handler_result on_ping(struct mitm *mitm, struct sk_buff *skb)
{
    uint16_t protocol = ntohs(vlan_get_protocol(skb));
	uint8_t *header = skb_mac_header(skb);

	// If IPv4...
	if (protocol == ETH_P_IP) {
		// Find IP header.
		struct iphdr *iph = ip_hdr(skb);

		// ICMP...
		if (iph->protocol == IPPROTO_ICMP) {
			int offset = iph->ihl << 2;
			uint8_t *ip_payload = (skb->data + offset);
			struct icmphdr *icmph = (struct icmphdr *)ip_payload;
			// If ping request...
			if (icmph->type == ICMP_ECHO) {
			    __be32 tmp;
                netdev_info(mitm->dev, "Intercept PING request\n");
				// Swap ETH addresses.
				eth_swap_addr(skb);
				// Swap IP addresses.
				tmp = iph->daddr;
				iph->daddr = iph->saddr;
				iph->saddr = tmp;
				// Fix IP checksum.
				iph->check = 0;
				iph->check = ip_fast_csum(iph, iph->ihl);
				// Change ping request into a reply.
				icmph->type = ICMP_ECHOREPLY;
				// Fix ICMP checksum.
				icmph->checksum = 0;
				icmph->checksum = ip_compute_csum(icmph, skb_tail_pointer(skb) - ip_payload);
				// Send this packet directly back.
				// ->data points to eth header.
				skb_push(skb, skb->data - header);
				return MITM_REPLY;
			}
		}
	}

	return MITM_FORWARD;
}

enum mitm_handler_result forward(struct mitm *mitm __maybe_unused, struct sk_buff *skb __maybe_unused)
{
    uint16_t protocol = ntohs(vlan_get_protocol(skb));
//    uint8_t *header = skb_mac_header(skb);

    // If IPv4...
    if (protocol == ETH_P_IP) {
        // Find IP header.
        struct iphdr *iph = ip_hdr(skb);
//        struct ethhdr *eth = (struct ethhdr *) header;
//		is_broadcast_ether_addr(eth->h_dest);
        // UDP ...
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = udp_hdr(skb);

//            uint16_t sport = ntohs(udph->source);
//            uint16_t dport = ntohs(udph->dest);

            netdev_info(mitm->dev, "forward an UDP packet\n");
//            netdev_info(mitm->dev, "  Source:\n");
//            netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_source);
//            netdev_info(mitm->dev, "    IP: %pI4\n", &iph->saddr);
//            netdev_info(mitm->dev, "    Port: %hu\n", sport);
//            netdev_info(mitm->dev, "  Dest:\n");
//            netdev_info(mitm->dev, "    MAC: %pM\n", eth->h_dest);
//            netdev_info(mitm->dev, "    IP: %pI4\n", &iph->daddr);
//            netdev_info(mitm->dev, "    Port: %hu\n", dport);

            return MITM_FORWARD;
        }
    }

	return MITM_FORWARD;
}
