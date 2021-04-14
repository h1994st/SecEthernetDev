#!/usr/bin/env bash

sh -c 'echo > /sys/kernel/debug/mitm0/slave'

NETNS0_EXEC="ip netns exec netns0"
$NETNS0_EXEC ip addr flush dev mitm0
