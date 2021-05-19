`mitm.c` is a fork from [a3f/mitm0](https://github.com/a3f/mitm0)

## QEMU dev encironment

```bash
mount -t debugfs none /sys/kernel/debug
```

## Testing `mitm0` w/o Docker

1. Configure network namespaces

    ```bash
    sudo ip netns add netns0  # sender
    sudo ip netns add netns1  # receiver, we can have more receivers
    sudo ip netns add netns2  # authenticator
    ```

2. Create virtual interfaces and assign namespaces

    ```bash
    sudo ip link add veth0 type veth peer name ceth0
    sudo ip link add veth1 type veth peer name ceth1

    sudo ip link set ceth0 netns netns0
    sudo ip link set ceth1 netns netns1

    sudo ip link set veth0 netns netns2
    sudo ip link set veth1 netns netns2
    ```

3. Configure the bridge

    ```bash
    # enter into netns2
    sudo nsenter --net=/var/run/netns/netns2 bash

    # add a bridge
    ip link add br0 type bridge
    ip link set br0 up

    # connect virtual interfaces
    ip link set veth0 master br0
    ip link set veth1 master br0
    ```

4. Configure addresses for sender and receiver

    ```bash
    # enter into netns0
    sudo nsenter --net=/var/run/netns/netns0 bash

    # set address for ceth0
    ip link set ceth0 up
    ip addr add 10.0.0.2/24 dev ceth0

    # enter into netns1
    sudo nsenter --net=/var/run/netns/netns1 bash

    # set address for ceth1
    ip link set ceth1 up
    ip addr add 10.0.0.3/24 dev ceth1
    ```

## `mitm0` with Docker container

1. Docker has its own network namespace, which can be inspected as follow:

    ```bash
    lsns -t net

    # enter into a network namespace
    sudo nsenter --net=/run/docker/netns/<...> bash
    ```

2. At the host machine:

    ```bash
    # vethxxxxxxx corresponds to the container
    sudo ip link set dev vethxxxxxxx down

    # disconnect the virtual interface with the bridge
    sudo ip link set dev vethxxxxxxx nomaster

    # enslave the virtual interface
    sudo sh -c 'printf vethxxxxxxx > /sys/kernel/debug/mitm0/slave'

    # connect mitm0 with the bridge
    sudo ip link set dev mitm0 master br-yyyyyyyy

    # bring the virtual interface up
    sudo ip link set dev vethxxxxxxx up
    ```

References:

- https://dev.to/polarbit/how-docker-container-networking-works-mimic-it-using-linux-network-namespaces-9mj
- https://zhuanlan.zhihu.com/p/346440595
- https://www.cnblogs.com/evan-liang/p/12271468.html

## Instantiate a Docker container for the authenticator

1. Create a container w/o a network connected

    ```bash
    docker run -it -d \
        --network none \
        --mac-address 02:42:ac:11:00:01 \
        --name=authenticator --hostname=authenticator \
        --privileged \
        h1994st/sec_eval
    ```

2. Move all virtual interfaces on the host machine to the namespace of the newly created Docker container

    ```bash
    # find the proc id of the newly created network namespace
    lsns -t net

    # make Docker network namespace visible to iproute2
    sudo ln -sf /proc/<...>/ns/net /var/run/netns/authenticator

    # now, it should be visible
    ip netns list

    # move virtual interfaces to the newly created namespace
    sudo ip link set vethxxxxxxx netns authenticator
    ```

3. Create a bridge device in the newly created namespace (i.e., the authenticator's namespace) and connect virtual interfaces with it

    ```bash
    sudo nsenter --net=/var/run/netns/authenticator bash

    ip link add br0 type bridge
    ip link set br0 up

    # connect virtual interfaces with the bridge
    ip link set vethxxxxxxx master br0
    ```

## Setup Linux+QEMU Development Environment

- Use `linux.config` as the configuration file
    - `PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig make ARCH=x86_64 xconfig`
    - Load `linux.config`
    - Save as `.config` to the root directory of Linux source codes
- TODO: buildroot configurations

Reference:

- <https://medium.com/@daeseok.youn/prepare-the-environment-for-developing-linux-kernel-with-qemu-c55e37ba8ade>
