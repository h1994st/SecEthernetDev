`mitm.c` is a fork from [a3f/mitm0](https://github.com/a3f/mitm0)

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
