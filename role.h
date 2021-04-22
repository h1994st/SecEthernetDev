//
// Created by h1994st on 4/15/21.
//

#ifndef SECETHERNETDEV_ROLE_H
#define SECETHERNETDEV_ROLE_H

#include "mitm.h"

enum mitm_handler_result mitm_from_slave(struct mitm *mitm, struct sk_buff *skb);
enum mitm_handler_result mitm_from_master(struct mitm *mitm, struct sk_buff *skb);

enum mitm_handler_result forward(struct mitm *mitm __maybe_unused, struct sk_buff *skb __maybe_unused);

enum mitm_handler_result on_ping(struct mitm *mitm, struct sk_buff *skb);

#endif //SECETHERNETDEV_ROLE_H
