//
// Created by h1994st on 4/15/21.
//

#ifndef SECETHERNETDEV_AUTHENTICATOR_H
#define SECETHERNETDEV_AUTHENTICATOR_H

#include "role.h"

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>

#define NUM_BR_NF_HOOKS 3
extern struct nf_hook_ops br_debug_nf_ops[NUM_BR_NF_HOOKS];
#endif /* IS_ENABLED(CONFIG_BRIDGE_NETFILTER) */

// 100 ms
#define NET_MONITOR_DELAY 100

#define NET_MONITOR_MAX_NUM 8
extern u64 dev_rx_bytes[NET_MONITOR_MAX_NUM];

#ifdef MITM_DOS_PROTECTION
// Timer callback function
void net_monitor_cb(struct timer_list *timer);
#endif /* MITM_DOS_PROTECTION */

#endif  //SECETHERNETDEV_AUTHENTICATOR_H
