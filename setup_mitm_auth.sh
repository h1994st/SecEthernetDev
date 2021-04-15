#!/usr/bin/env bash

ip link set mitm_auth netns netns2

NETNS2_EXEC="ip netns exec netns2"

$NETNS2_EXEC ip link set br0 down
$NETNS2_EXEC ip link set mitm_auth up
sh -c 'printf br0 > /sys/kernel/debug/mitm_auth/slave'
$NETNS2_EXEC ip addr add 10.0.0.1/24 dev mitm_auth
#$NETNS2_EXEC ip addr flush dev ceth0
