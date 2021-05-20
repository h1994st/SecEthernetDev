//
// Created by h1994st on 5/20/21.
//

#ifndef SECETHERNETDEV_TESLA_CAN_UDP_COMMON_H
#define SECETHERNETDEV_TESLA_CAN_UDP_COMMON_H

// sender - TESLA server
#define SENDER_PORT 2345
#define SENDER_UDPOUT 2346

// receiver - TESLA client
#define RECEIVER_PORT 8888

#define IP_ADDR_FORMAT(x)                                 \
  (int) (((x) >> 24) & 0xff), (int) (((x) >> 16) & 0xff), \
      (int) (((x) >> 8) & 0xff), (int) ((x) &0xff)

#define CHECKNEGPE(exp)                          \
  if ((exp) == -1) {                             \
    printf(" Error %s: %i", __FILE__, __LINE__); \
    exit(-1);                                    \
  }

#endif//SECETHERNETDEV_TESLA_CAN_UDP_COMMON_H
