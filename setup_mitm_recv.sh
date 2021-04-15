#!/usr/bin/env bash

ip link set mitm_recv netns netns1

NETNS1_EXEC="ip netns exec netns1"

$NETNS1_EXEC ip link set ceth1 down
$NETNS1_EXEC ip link set mitm_recv up
sh -c 'printf ceth1 > /sys/kernel/debug/mitm_recv/slave'
$NETNS1_EXEC ip addr add 10.0.0.3/24 dev mitm_recv
$NETNS1_EXEC ip addr flush dev ceth1
