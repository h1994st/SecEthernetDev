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
#endif

#endif //SECETHERNETDEV_AUTHENTICATOR_H
