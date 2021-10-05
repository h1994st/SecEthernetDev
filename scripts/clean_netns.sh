#!/usr/bin/env bash

NETNS0_EXEC="ip netns exec netns0"
NETNS1_EXEC="ip netns exec netns1"
NETNS2_EXEC="ip netns exec netns2"

$NETNS2_EXEC ip link del br0
$NETNS2_EXEC ip link del veth0
$NETNS2_EXEC ip link del veth1

echo 'netns2:'
$NETNS2_EXEC ip link

echo 'netns1:'
$NETNS1_EXEC ip link

echo 'netns0:'
$NETNS0_EXEC ip link

ip netns del netns0  # sender
ip netns del netns1  # receiver, we can have more receivers
ip netns del netns2  # authenticator
