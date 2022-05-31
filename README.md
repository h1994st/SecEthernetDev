# Gatekeeper Modules

## Prerequisite

- Ubuntu 18.04
- Linux kernel 5.4.0
- Linux kernel header files: `sudo apt install linux-headers-$(uname -r)`
- Install wolfSSL 4.8.1 (commit [`e5caf5`](https://github.com/wolfSSL/wolfssl/tree/e5caf5124cf971553933b9c85cfabb6b5027b884) recommended)
- CMake (> 3.10)

## Get Started

Here is a brief introduction of all targets:

- `kernel_modules`: mainly for the authenticator (i.e., targets with the prefix of `mitm_auth`)
- `common`: common libraries for Gatekeeper sender/receiver
- `can_udp_raw`, `lidar_udp_raw`: replay CAN/LiDAR data over UDP via raw socket, acting as Gatekeeper sender/receiver
- `can_udp`, `lidar_udp`: replay CAN/LiDAR data over UDP (can be used with `mitm_snd`/`mitm_recv`, deprecated now)
- `tesla`: TESLA protocol library
- `tesla_can_udp`, `tesla_lidar_udp`: replay CAN/LiDAR data over UDP, using TESLA protocol
- `benchmark`: benchmark applications the time-lock puzzle
- `tests`: unit tests

### Using CMake to build

```bash
mkdir build
cd build
cmake ..
make
cp can_udp/udp_client can_udp/udp_server \
    can_udp_raw/udp_client_raw can_udp_raw/udp_server_raw \
    tesla_can_udp/tesla_udp_client tesla_can_udp/tesla_udp_server \
    lidar_udp_raw/lidar_udp_client_raw lidar_udp_raw/lidar_udp_server_raw \
    tesla_lidar_udp/tesla_lidar_udp_client tesla_lidar_udp/tesla_lidar_udp_server \
    tesla/libtesla.so \
    </path/to/SecEthernetEval>
```

***NOTE: [SecEthernetEval](https://github.com/h1994st/SecEthernetEval)***

### Using Makefile for Kernel Modules

```bash
cd kernel_modules
# MITM_ROLE=2, for the authenticator
make MITM_ROLE=2
# Can specify other versions of Linux kernel header files
make LINUX_DIR=</path/to/header/files> MITM_ROLE=2
```

Please refer to [NOTES.md](NOTES.md) for development notes.
