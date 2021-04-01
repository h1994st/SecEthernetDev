`mitm.c` is a fork from [a3f/mitm0](https://github.com/a3f/mitm0)

## `mitm0` with Docker container

Docker has its own network namespace, which can be inspected as follow:

```bash
lsns -t net

# enter into a network namespace
sudo nsenter --net=/run/docker/netns/<...> bash
```

After entering into the network namespace of a container, we need to bring the virtual ethernet interface down

```bash
ip link set dev eth0 down
```

Then, at the host machine:

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

At the network namespace of the container:

```bash
ip link set dev eth0 up
```

References:

- https://dev.to/polarbit/how-docker-container-networking-works-mimic-it-using-linux-network-namespaces-9mj
- https://zhuanlan.zhihu.com/p/346440595
- https://www.cnblogs.com/evan-liang/p/12271468.html
