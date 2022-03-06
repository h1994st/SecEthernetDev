//
// Created by h1994st on 4/15/21.
//

#ifndef SECETHERNETDEV_AUTHENTICATOR_H
#define SECETHERNETDEV_AUTHENTICATOR_H

#include "role.h"

#ifdef MITM_DOS_PROTECTION
// unit: ms
#define NET_MONITOR_DELAY 100

#define NET_MONITOR_MAX_NUM 8
extern u64 dev_rx_bytes[NET_MONITOR_MAX_NUM];

// Timer callback function
void net_monitor_cb(struct timer_list *timer);
#endif /* MITM_DOS_PROTECTION */

#endif  //SECETHERNETDEV_AUTHENTICATOR_H
