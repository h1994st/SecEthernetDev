#!/usr/bin/env bash

ip link set mitm0 netns netns0

NETNS0_EXEC="ip netns exec netns0"

$NETNS0_EXEC ip link set ceth0 down
$NETNS0_EXEC ip link set mitm0 up
sh -c 'printf ceth0 > /sys/kernel/debug/mitm0/slave'
$NETNS0_EXEC ip addr add 10.0.0.2/24 dev mitm0
