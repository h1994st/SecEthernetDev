ifndef MITM_ROLE
    override MITM_ROLE = 2
endif

ifeq ($(MITM_ROLE),0)
    obj-m := mitm_snd.o
    mitm_snd-objs := mitm.o role.o sender.o
endif

ifeq ($(MITM_ROLE),1)
    obj-m := mitm_recv.o
    mitm_recv-objs := mitm.o role.o receiver.o
endif

ifeq ($(MITM_ROLE),2)
    obj-m := mitm_auth.o
    mitm_auth-objs := mitm.o role.o authenticator.o
endif

MY_CFLAGS += -g -DDEBUG -DMITM_ROLE=${MITM_ROLE}
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

SLAVE_IF ?= enp0s8

# LINUX_DIR ?= /lib/modules/$(shell uname -r)/build

LINUX_DIR ?= /home/h1994st/Developer/Research/SecureEthernet/linux-5.4

all:
	$(MAKE) -C $(LINUX_DIR) M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	$(MAKE) -C $(LINUX_DIR) M=$(PWD) clean
insmod:
	sudo insmod $(obj-m:.o=.ko)
	dmesg -wH
rmmod:
	sudo rmmod $(obj-m:.o=)
	dmesg -wH
probe:
	@lsmod | grep $(obj-m:.o=) || echo Module not loaded.
slave_up:
	sudo ifconfig $(SLAVE_IF) up
	sudo dhclient $(SLAVE_IF)
	nc -l $(shell ifconfig mitm0 | grep "inet " | awk -F'[: ]+' '{ print $$4 }') 1337

nc:
	nc -l $(shell ifconfig mitm0 | grep "inet " | awk -F'[: ]+' '{ print $$4 }') 1337

slave_down:
	sudo ifconfig $(SLAVE_IF) down

enslave:
	sudo sh -c 'printf $(SLAVE_IF) > /sys/kernel/debug/mitm0/slave'
release:
	sudo sh -c 'echo > /sys/kernel/debug/mitm0/slave'
get_slave:
	sudo cat /sys/kernel/debug/mitm0/slave
flush_slave_ip:
	sudo ip addr flush dev $(SLAVE_IF)

dmesg:
	dmesg -wH
