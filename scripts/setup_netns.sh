#!/usr/bin/env bash

ip netns add netns0  # sender
ip netns add netns1  # receiver, we can have more receivers
ip netns add netns2  # authenticator

ip link add veth0 type veth peer name ceth0
ip link add veth1 type veth peer name ceth1

ip link set ceth0 netns netns0
ip link set ceth1 netns netns1

ip link set veth0 netns netns2
ip link set veth1 netns netns2

# netns2
NETNS2_EXEC="ip netns exec netns2"

# add a bridge
$NETNS2_EXEC ip link add br0 type bridge
$NETNS2_EXEC ip link set br0 up

# connect virtual interfaces
$NETNS2_EXEC ip link set veth0 master br0
$NETNS2_EXEC ip link set veth1 master br0

$NETNS2_EXEC ip link set veth0 up
$NETNS2_EXEC ip link set veth1 up

echo 'Finish setting up netns2'
$NETNS2_EXEC ip link

# netns0
NETNS0_EXEC="ip netns exec netns0"

# set address for ceth0
$NETNS0_EXEC ip link set ceth0 up
$NETNS0_EXEC ip addr add 10.0.0.2/24 dev ceth0

echo 'Finish setting up netns0'
$NETNS0_EXEC ip a

# netns1
NETNS1_EXEC="ip netns exec netns1"

# set address for ceth1
$NETNS1_EXEC ip link set ceth1 up
$NETNS1_EXEC ip addr add 10.0.0.3/24 dev ceth1

echo 'Finish setting up netns1'
$NETNS1_EXEC ip a
