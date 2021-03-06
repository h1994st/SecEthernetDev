/*
 * mitm.c  --  man-in-the-middle another network interface
 * Copyright (C) 2017 Ahmad Fatoum
 *
 * Based on the drivers/net/bonding/bond_main.c
 * Copyright 1999, Thomas Davis, tadavis@lbl.gov.
 * Licensed under the GPL. Itself based on dummy.c, and eql.c devices.
 */

#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <linux/version.h>

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netpoll.h>
#include <linux/sched.h>
#include <linux/types.h>

#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/sch_generic.h>

#include "mitm.h"
#include "role.h"

#include "mpi/mpi.h"

#define DRV_VERSION "0.01"
#define DRV_RELDATE "2020-04-14"
#define DRV_DESCRIPTION "Network driver Man-In-The-Middle'r"
#if (MITM_ROLE == 0)

#define DRV_NAME "mitm_snd"

#elif (MITM_ROLE == 1)

#ifdef MITM_DOS_PROTECTION
#define DRV_NAME "mitm_recv_dos"
#include "receiver_dos.h"
#else
#define DRV_NAME "mitm_recv"
#include "receiver.h"
#endif /* MITM_DOS_PROTECTION */

#elif (MITM_ROLE == 2)

#define DRV_NAME "mitm_auth"
#include "authenticator.h"

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#endif

#ifdef MITM_DOS_PROTECTION
#include "time_lock_puzzle.h"
#endif

#else
#error "MITM_ROLE is not defined!"
#endif

static bool use_qdisc = true;
module_param(use_qdisc, bool, 0000);
MODULE_PARM_DESC(use_qdisc, "Use Qdisc? 0 = no, 1 = yes (default)");

static bool use_netpoll;
#ifdef CONFIG_NETPOLL
MODULE_PARM_DESC(
    use_netpoll, "Use netpoll if possible? 0 = no (default), 1 = yes");
module_param(use_netpoll, bool, 0000);
#endif

static bool intercept_ping = true;
MODULE_PARM_DESC(
    intercept_ping,
    "Enable ICMP echo (ping) interception example code? 0 = no, 1 = yes "
    "(default)");
module_param(intercept_ping, bool, 0000);

/*----------------------------------- Rx ------------------------------------*/
/*
 * Receive a packet: retrieve, encapsulate and pass over to upper levels
 */
static rx_handler_result_t mitm_handle_frame(struct sk_buff **pskb) {
  struct sk_buff *skb = *pskb;
  struct mitm *mitm;

  skb = skb_share_check(skb, GFP_ATOMIC);
  if (unlikely(!skb)) return RX_HANDLER_CONSUMED;

  *pskb = skb;

  mitm = rcu_dereference(skb->dev->rx_handler_data);

  switch (mitm->handle_ingress(mitm, skb)) {
    case MITM_FORWARD:  // Associate packet with master.
      skb->dev = mitm->dev;
      return RX_HANDLER_ANOTHER;
    case MITM_REPLY:  // Packet already associated with the slave.
      // Mode-dependent transmit.
      (void) mitm->xmit(mitm, skb);
      // Consumed because is queued elsewhere.
    case MITM_CONSUMED: return RX_HANDLER_CONSUMED;
    default:  // Drop.
      atomic_long_inc(&(skb->dev->rx_dropped));
      dev_kfree_skb_any(skb);
      return RX_HANDLER_CONSUMED;
  }
}

/*----------------------------------- Tx ------------------------------------*/

static int __packet_direct_xmit(struct sk_buff *skb);

static netdev_tx_t
mitm_start_xmit(struct sk_buff *skb, struct net_device *dev) {
  struct mitm *mitm = netdev_priv(dev);
  struct slave *slave = mitm_slave(mitm);

  BUILD_BUG_ON(
      sizeof(skb->queue_mapping)
      != sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
  skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);

#if 0 /* we could use this for notification of tx if we are sure no one else uses it */
	skb_shinfo(skb)->destructor_arg = pBuffer_p;
	skb->destructor = txPacketHandler;
#endif

  /* TODO rcu lock? */

  if (slave) {
    switch (mitm->handle_egress(mitm, skb)) {
      case MITM_FORWARD:
        // Associate the packet with the slave
        skb->dev = slave->dev;
        // Mode-dependent transmit.
        return mitm->xmit(mitm, skb);
      case MITM_CONSUMED: return NETDEV_TX_OK;
      default: break;
    }
  }

  atomic_long_inc(&dev->tx_dropped);
  dev_kfree_skb_any(skb);

  return NETDEV_TX_OK;
}

static inline netdev_tx_t __packet_xmit_irq_enabled(
    netdev_tx_t (*xmit)(struct sk_buff *), struct sk_buff *skb) {
  netdev_tx_t ret;
  bool enable_irq =
      irqs_disabled(); /* always false in our current setup, but your use case may change */

  if (enable_irq) local_irq_enable();
  ret = xmit(skb);
  if (enable_irq) local_irq_disable();

  return ret;
}

static netdev_tx_t packet_queue_xmit(struct mitm *mitm, struct sk_buff *skb) {
  BUILD_BUG_ON(
      sizeof(skb->queue_mapping)
      != sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
  skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);

  return __packet_xmit_irq_enabled(dev_queue_xmit, skb);
}

static netdev_tx_t packet_direct_xmit(struct mitm *mitm, struct sk_buff *skb) {
  return __packet_xmit_irq_enabled(__packet_direct_xmit, skb);
}

static netdev_tx_t packet_netpoll_xmit(struct mitm *mitm, struct sk_buff *skb) {
#ifdef CONFIG_NETPOLL
  netpoll_send_skb(&mitm->np, skb);
#endif
  return NETDEV_TX_OK;
}

/* Taken out of net/packet/af_packet.c */
static u16 packet_pick_tx_queue(struct sk_buff *skb) {
  struct net_device *dev = skb->dev;
  const struct net_device_ops *ops = dev->netdev_ops;
  int cpu = raw_smp_processor_id();
  u16 queue_index;

#ifdef CONFIG_XPS
  skb->sender_cpu = cpu + 1;
#endif
  skb_record_rx_queue(skb, cpu % dev->real_num_tx_queues);
  if (ops->ndo_select_queue) {
    queue_index = ops->ndo_select_queue(dev, skb, NULL);
    queue_index = netdev_cap_txqueue(dev, queue_index);
  } else {
    queue_index = netdev_pick_tx(dev, skb, NULL);
  }

  return queue_index;
}

/*
 * Taken out of net/packet/af_packet.c
 * Original function: packet_direct_xmit
 */
static int __packet_direct_xmit(struct sk_buff *skb) {
  return dev_direct_xmit(skb, packet_pick_tx_queue(skb));
}

/*-------------------------- Bonding Notification ---------------------------*/
/* Taken out of net/bonding/bond_main.c */
static int mitm_master_upper_dev_link(
    struct mitm *mitm, struct slave *slave, struct netlink_ext_ack *extack) {
  /* we aggregate everything into one link, so that's technically a broadcast */
  struct netdev_lag_upper_info lag_upper_info = {
      .tx_type = NETDEV_LAG_TX_TYPE_BROADCAST,
      .hash_type = NETDEV_LAG_HASH_NONE};

  return netdev_master_upper_dev_link(
      slave->dev, mitm->dev, slave, &lag_upper_info, extack);
}

static void mitm_upper_dev_unlink(struct mitm *mitm, struct slave *slave) {
  netdev_upper_dev_unlink(slave->dev, mitm->dev);
  slave->dev->flags &= ~IFF_SLAVE;
}
/* FIXME unused */
#if 0
static void bond_lower_state_changed(struct slave *slave)
{
	struct netdev_lag_lower_state_info info;

	info.link_up = slave->link_up;
	info.tx_enabled = slave->dev != NULL;
	netdev_lower_state_changed(slave->dev, &info);
}
#endif

/**
 * mitm_set_dev_addr - clone slave's address to bond
 * @mitm_dev: bond net device
 * @slave_dev: slave net device
 *
 * Should be called with RTNL held.
 */
static int
mitm_set_dev_addr(struct net_device *mitm_dev, struct net_device *slave_dev) {
  int err;

  netdev_dbg(
      mitm_dev,
      "mitm_dev=%p slave_dev=%p slave_dev->name=%s slave_dev->addr_len=%d\n",
      mitm_dev, slave_dev, slave_dev->name, slave_dev->addr_len);
  err = dev_pre_changeaddr_notify(mitm_dev, slave_dev->dev_addr, NULL);
  if (err) return err;

  memcpy(mitm_dev->dev_addr, slave_dev->dev_addr, slave_dev->addr_len);
  mitm_dev->addr_assign_type = NET_ADDR_STOLEN;
  call_netdevice_notifiers(NETDEV_CHANGEADDR, mitm_dev);
  return 0;
}

/* Set carrier state of master on if there's a slave
 *
 * Returns zero if carrier state does not change, nonzero if it does.
 */
static int mitm_set_carrier(struct mitm *mitm) {
  struct slave *slave = mitm_slave(mitm);

  if (!slave) {
    if (netif_carrier_ok(mitm->dev)) {
      netif_carrier_off(mitm->dev);
      return 1;
    }

    return 0;
  }

  if (!netif_carrier_ok(mitm->dev)) {
    netif_carrier_on(mitm->dev);
    return 1;
  }

  return 0;
}

/*-------------------------------- Netfilter --------------------------------*/
#if (MITM_ROLE == 2)
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>

static int br_debug_nf_register(struct net *net) {
  if (net_eq(net, &init_net)) {
    // do not hook the root network namespace
    return 0;
  }

#ifndef MITM_DOS_PROTECTION
  return nf_register_net_hooks(
      net, br_debug_nf_ops, ARRAY_SIZE(br_debug_nf_ops));
#else
  // do not hook anything
  return 0;
#endif /* MITM_DOS_PROTECTION */
}

static void br_debug_nf_unregister(struct net *net) {
  if (net_eq(net, &init_net)) {
    // no hook for the root network namespace
    return;
  }

#ifndef MITM_DOS_PROTECTION
  nf_unregister_net_hooks(net, br_debug_nf_ops, ARRAY_SIZE(br_debug_nf_ops));
#endif /* MITM_DOS_PROTECTION */
}
#endif
#endif

#ifdef MITM_DOS_PROTECTION
/*---------------------------- Timer init/fini ------------------------------*/
static int net_monitor_init(struct mitm *mitm) {
  int err;
  int i = 0;
  struct slave *slave = mitm_slave(mitm);
  struct net_device *slave_dev = slave->dev;
  struct rtnl_link_stats64 stats;
  struct timer_list *timer;

  // initialize traffic stats
  dev_get_stats(slave_dev, &stats);
  dev_rx_bytes[i] = stats.rx_bytes;
  netdev_info(
      mitm->dev, "Port (%s): %llu bytes\n", slave_dev->name, stats.rx_bytes);

  // initialize the timer
  timer = &mitm->net_monitor_timer;
  timer_setup(timer, net_monitor_cb, 0);
  err = mod_timer(timer, jiffies + msecs_to_jiffies(NET_MONITOR_DELAY));
  if (err) {
    // failed to set timer
    netdev_err(mitm->dev, "Failed to set timer\n");
    return err;
  }

  netdev_info(mitm->dev, "Set timer: %d ms\n", NET_MONITOR_DELAY);

  return 0;
}

static void net_monitor_exit(struct mitm *mitm) {
  netdev_info(mitm->dev, "Delete network monitor timer\n");
  del_timer(&mitm->net_monitor_timer);
}

static int time_lock_puzzle_init(struct mitm *mitm) {
  time_lock_puzzle_ctx *puzzle;
  time_lock_puzzle *payload;

  puzzle = time_lock_puzzle_ctx_alloc();
  if (!puzzle) {
    // failed to allocate puzzle context
    netdev_err(mitm->dev, "Failed to allocate the puzzle context\n");
    return -1;
  }
  // TODO: adjust this value
  puzzle->S = 1;

  payload = kzalloc(sizeof(time_lock_puzzle), GFP_KERNEL);
  if (!payload) {
    // failed to allocate memory for puzzle payload
    netdev_err(mitm->dev, "Failed to allocate the puzzle payload\n");
    time_lock_puzzle_ctx_free(puzzle);
    return -1;
  }

  mitm->puzzle = puzzle;
  mitm->payload = payload;

  return 0;
}

static void time_lock_puzzle_exit(struct mitm *mitm) {
  if (mitm->puzzle) time_lock_puzzle_ctx_free(mitm->puzzle);
  if (mitm->payload) kfree(mitm->payload);
}
#endif /* MITM_DOS_PROTECTION */

/*--------------------------------- Slavery ---------------------------------*/

static int mitm_enslave(
    struct net_device *mitm_dev, struct net_device *slave_dev,
    struct netlink_ext_ack *extack) {
  struct mitm *mitm = netdev_priv(mitm_dev);
  int res = 0;

#ifndef MITM_DISABLE
#if (MITM_ROLE == 2)
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER) /* w/ bridge netfilter */
  int i;                                // used later
  struct net *mitm_ns = dev_net(mitm_dev);
#endif /* IS_ENABLED(CONFIG_BRIDGE_NETFILTER) */

  /* We only accept bridge device for the authenticator */
  if (!netif_is_bridge_master(slave_dev)) {
    netdev_err(
        mitm_dev, "mitm authenticator can only enslave a bridge device\n");
    return -EPERM;
  }
  netdev_info(mitm_dev, "Enslaving a bridge master device\n");
#endif /* MITM_ROLE == 2 */
#endif

  /* We only mitm one device */
  if (mitm_has_slave(mitm)) {
    netdev_err(mitm_dev, "Error: mitm can only have one slave\n");
    return -EBUSY;
  }

  /* already in-use? */
  if (netdev_is_rx_handler_busy(slave_dev)) {
    netdev_err(mitm_dev, "Error: Device is in use and cannot be enslaved\n");
    return -EBUSY;
  }

  if (mitm_dev == slave_dev) {
    netdev_err(mitm_dev, "mitm cannot enslave itself.\n");
    return -EPERM;
  }

  if (slave_dev->type != ARPHRD_ETHER) {
    netdev_err(mitm_dev, "mitm can only enslave ethernet devices.\n");
    return -EPERM;
  }

  /* Old ifenslave binaries are no longer supported.  These can
	 * be identified with moderate accuracy by the state of the slave:
	 * the current ifenslave will set the interface down prior to
	 * enslaving it; the old ifenslave will not.
	 */
  if (slave_dev->flags & IFF_UP) {
    NL_SET_ERR_MSG(extack, "Device can not be enslaved while up");
    netdev_err(
        mitm_dev, "%s is up - this may be due to an out of date ifenslave\n",
        slave_dev->name);
    return -EPERM;
  }

  call_netdevice_notifiers(NETDEV_JOIN, slave_dev);

  res = mitm_set_dev_addr(mitm->dev, slave_dev);
  if (res) {
    netdev_err(mitm_dev, "Setting dev address failed\n");
    goto err_unslave;
  }

  mitm->slave.dev = slave_dev;

  /* set slave flag before open to prevent IPv6 addrconf */
  slave_dev->flags |= IFF_SLAVE;

  /* open the slave since the application closed it */
  res = dev_open(slave_dev, extack);
  if (res) {
    netdev_err(mitm_dev, "Opening slave %s failed\n", slave_dev->name);
    goto err_unslave;
  }

  slave_dev->priv_flags |= IFF_BONDING;

  res = netdev_rx_handler_register(slave_dev, mitm_handle_frame, mitm);
  if (res) {
    netdev_err(mitm_dev, "Error %d calling netdev_rx_handler_register\n", res);
    goto err_close;
  }

  res = mitm_master_upper_dev_link(mitm, &mitm->slave, extack);
  if (res) {
    netdev_err(mitm_dev, "Error %d calling mitm_master_upper_dev_link\n", res);
    goto err_unregister;
  }

#ifndef MITM_DISABLE
#if (MITM_ROLE == 2) /* authenticator */
  res = dev_set_promiscuity(slave_dev, 1);
  if (res) goto err_upper_unlink;

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER) /* w/ bridge netfilter */
  /* set private data for hooks */
  for (i = 0; i < ARRAY_SIZE(br_debug_nf_ops); ++i) {
    br_debug_nf_ops[i].priv = (void *) mitm;
  }

  netdev_info(mitm_dev, "Registering netfilter hooks\n");
  res = br_debug_nf_register(mitm_ns);
  if (res) goto err_upper_unlink;
#endif
#endif
#endif

  /* set promiscuity level to new slave */
  if (mitm_dev->flags & IFF_PROMISC) {
    res = dev_set_promiscuity(slave_dev, 1);
    if (res) goto err_upper_unlink;
  }

  /* set allmulti level to new slave */
  if (mitm_dev->flags & IFF_ALLMULTI) {
    res = dev_set_allmulti(slave_dev, 1);
    if (res) {
      if (slave_dev->flags & IFF_PROMISC) dev_set_promiscuity(slave_dev, -1);
      goto err_upper_unlink;
    }
  }

  netif_addr_lock_bh(mitm_dev);
  dev_mc_sync_multiple(slave_dev, mitm_dev);
  dev_uc_sync_multiple(slave_dev, mitm_dev);
  netif_addr_unlock_bh(mitm_dev);

  mitm_set_carrier(mitm);

  netdev_info(mitm_dev, "Enslaving %s interface\n", slave_dev->name);

#if MITM_ROLE == 1
#ifdef MITM_DOS_PROTECTION
  /* Initialize network monitor timer */
  res = net_monitor_init(mitm);
  if (res) {
    // cannot initialize the timer and enable DoS protection
    netdev_warn(mitm_dev, "net_monitor_init failed: err %d\n", res);
  }
#endif /* MITM_DOS_PROTECTION */
#endif

  return 0;

  /* Undo stages on error */
err_upper_unlink:
  mitm_upper_dev_unlink(mitm, &mitm->slave);

err_unregister:
  netdev_rx_handler_unregister(slave_dev);

//err_detach:
err_close:
  slave_dev->priv_flags &= ~IFF_BONDING;
  dev_close(slave_dev);

err_unslave:
  slave_dev->flags &= ~IFF_SLAVE;
  mitm->slave.dev = NULL;
  if (ether_addr_equal_64bits(mitm_dev->dev_addr, slave_dev->dev_addr))
    eth_hw_addr_random(mitm_dev);

  return res;
}

/*
 * drivers/net/bonding/bond_main.c
 * Original function: __bond_release_one
 */
/* Try to release the slave device <slave> from the bond device <master>
 * It is legal to access curr_active_slave without a lock because all the function
 * is RTNL-locked. If "all" is true it means that the function is being called
 * while destroying a bond interface and all slaves are being released.
 *
 * The rules for slave state should be:
 *   for Active/Backup:
 *     Active stays on all backups go down
 *   for Bonded connections:
 *     The first up interface should be left on and all others downed.
 */
static int
mitm_emancipate(struct net_device *mitm_dev, struct net_device *slave_dev) {
  struct mitm *mitm = netdev_priv(mitm_dev);
  struct slave *slave;
  int old_flags = mitm_dev->flags;

#ifndef MITM_DISABLE
#if (MITM_ROLE == 2)
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER) /* w/ bridge netfilter */
  struct net *mitm_ns = dev_net(mitm_dev);
#endif /* IS_ENABLED(CONFIG_BRIDGE_NETFILTER) */
#endif /* MITM_ROLE == 2 */
#endif

  if (!slave_dev) slave_dev = mitm->slave.dev;

  if (!slave_dev) return 0; /* nothing to do */

#if MITM_ROLE == 1
#ifdef MITM_DOS_PROTECTION
  net_monitor_exit(mitm);
#endif /* MITM_DOS_PROTECTION */
#endif

  /* slave is not a slave or master is not master of this slave */
  if (!(slave_dev->flags & IFF_SLAVE)
      || !netdev_has_upper_dev(slave_dev, mitm_dev)) {
    netdev_err(mitm_dev, "cannot release %s\n", slave_dev->name);
    return -EINVAL;
  }

  slave = mitm_slave(mitm);
  if (!slave) {
    /* not a slave of this mitm */
    netdev_err(mitm_dev, "%s not enslaved\n", slave_dev->name);
    return -EINVAL;
  }

  mitm_upper_dev_unlink(mitm, slave);
  /* unregister rx_handler early so mitm_handle_frame wouldn't be called
	 * for this slave anymore.
	 */
  netdev_rx_handler_unregister(slave_dev);

  netdev_info(mitm_dev, "Releasing interface %s\n", slave_dev->name);

  mitm_set_carrier(mitm);
  eth_hw_addr_random(mitm_dev);
  call_netdevice_notifiers(NETDEV_CHANGEADDR, mitm->dev);
  call_netdevice_notifiers(NETDEV_RELEASE, mitm->dev);

#ifndef MITM_DISABLE
#if (MITM_ROLE == 2) /* authenticator */
  dev_set_promiscuity(slave_dev, -1);

#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER) /* w/ bridge netfilter */
  netdev_info(mitm_dev, "Unregistering netfilter hooks\n");
  br_debug_nf_unregister(mitm_ns);
#endif
#endif
#endif

  if (old_flags & IFF_PROMISC) dev_set_promiscuity(slave_dev, -1);

  if (old_flags & IFF_ALLMULTI) dev_set_allmulti(slave_dev, -1);

  /* Flush bond's hardware addresses from slave */
  dev_uc_unsync(slave_dev, mitm_dev);
  dev_mc_unsync(slave_dev, mitm_dev);

  dev_close(slave_dev);

  slave_dev->priv_flags &= ~IFF_BONDING;

  return 0;
}

/*-------------------------------- Interface --------------------------------*/

/*
 * Open and close
 */
int mitm_open(struct net_device *dev) {
  /* Neither bond not team call netif_(start|stop)_queue. why? */
  /* netif_start_queue(dev); */
  return 0;
}

int mitm_stop(struct net_device *dev) {
  /* netif_stop_queue(dev); */
  return 0;
}

static const struct net_device_ops mitm_netdev_ops = {
    .ndo_open = mitm_open,
    .ndo_stop = mitm_stop,
    .ndo_start_xmit = mitm_start_xmit,
};

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void mitm_setup(struct net_device *mitm_dev) {
  struct mitm *mitm = netdev_priv(mitm_dev);

  spin_lock_init(&mitm->lock);
  mitm->dev = mitm_dev;
  mitm->slave.dev = NULL;

  ether_setup(mitm_dev); /* assign some of the fields */

  mitm_dev->netdev_ops = &mitm_netdev_ops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 9)
  mitm_dev->needs_free_netdev = true;
#else
  mitm_dev->destructor = free_netdev;
#endif
}

/*--------------------------------- DebugFS ---------------------------------*/
static struct dentry *debugfs_dir;
static ssize_t debugfs_get_slave(
    struct file *file, char __user *buff, size_t count, loff_t *offset) {
  struct net_device *mitm_dev = file->f_inode->i_private;
  struct mitm *mitm = netdev_priv(mitm_dev);
  struct slave *slave = mitm_slave(mitm);

  if (!debugfs_dir) return -EIO;

  if (!slave) return -EAGAIN;

  return simple_read_from_buffer(
      buff, count, offset, slave->dev->name, strlen(slave->dev->name));
}
static ssize_t debugfs_set_slave(
    struct file *file, const char __user *buff, size_t count, loff_t *offset) {
  struct net_device *mitm_dev = file->f_inode->i_private;
  struct mitm *mitm = netdev_priv(mitm_dev);
  struct net_device *slave_dev;
  char ifname[IFNAMSIZ + 1];
  ssize_t nbytes, ret = 0, nulpos;
  struct net *mitm_ns = dev_net(mitm_dev);

  if (!debugfs_dir) return -EIO;

  nbytes =
      simple_write_to_buffer(ifname, sizeof(ifname) - 1, offset, buff, count);
  if (nbytes <= 0) return nbytes;

  nulpos = nbytes;
  if (ifname[nbytes - 1] == '\n') nulpos--;

  ifname[nulpos] = '\0';

  rtnl_lock();

  if (nulpos) {
    // find slave device under the same namespace as mitm device
    slave_dev = __dev_get_by_name(mitm_ns, ifname);

    if (!slave_dev) {
      netdev_err(mitm_dev, "%s() Failed to get slave dev\n", __func__);
      ret = -EINVAL;
      goto unlock;
    }

    netdev_info(
        slave_dev, "You want to enslave %s (%s)?\n", ifname, slave_dev->name);

    ret = mitm_enslave(mitm_dev, slave_dev, NULL);
    if (ret) goto unlock;

#ifdef CONFIG_NETPOLL
    if (use_netpoll) {
      mitm->np.name = "mitm-netpoll";
      strlcpy(mitm->np.dev_name, slave_dev->name, IFNAMSIZ);
      ret = __netpoll_setup(&mitm->np, slave_dev);
      if (ret < 0) {
        netdev_err(
            slave_dev, "%s() Failed to setup netpoll: error %zd\n", __func__,
            ret);
        mitm->np.dev = NULL;
        goto unlock;
      }
    }
#endif

    mitm->xmit = use_qdisc ? packet_queue_xmit :
        use_netpoll        ? packet_netpoll_xmit :
                             packet_direct_xmit;

    netdev_info(
        mitm_dev, "%s mode will be used on %s\n",
        use_qdisc       ? "Qdisc" :
            use_netpoll ? "Netpoll" :
                          "Direct-xmit",
        slave_dev->name);

  } else {
    mitm->xmit = NULL; /* FIXME might be racy... */
#ifdef CONFIG_NETPOLL
    if (mitm->np.dev) {
      netpoll_cleanup(&mitm->np);
      mitm->np.dev = NULL;
    }
#endif
    ret = mitm_emancipate(mitm_dev, NULL);
  }

unlock:
  rtnl_unlock();
  return ret == 0 ? nbytes : ret;
}
static const struct file_operations slave_fops = {
    .owner = THIS_MODULE,
    .read = debugfs_get_slave,
    .write = debugfs_set_slave,
};

/*---------------------------- Module init/fini -----------------------------*/
static struct net_device *mitm_dev;

int __init mitm_init_module(void) {
  int ret;
  struct mitm *mitm;
  struct crypto_shash *hmac_tfm;
#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
  struct crypto_akcipher *proof_tfm;
  struct akcipher_request *proof_req;
  uint8_t *xbuf[2];
#else
  struct crypto_shash *proof_tfm;
#endif /* MITM_AUTH_RSA */
#endif
#if MITM_ROLE == 1 || MITM_ROLE == 2
  struct crypto_shash *hash_tfm;
#endif

  /* Initialize MPI subsystem */
  mpi_init();

  /* Allocate the devices */
  mitm_dev =
      alloc_netdev(sizeof(struct mitm), DRV_NAME, NET_NAME_UNKNOWN, mitm_setup);
  if (!mitm_dev) return -ENOMEM;

  ret = register_netdev(mitm_dev);
  if (ret < 0) {
    netdev_err(
        mitm_dev, "Error %i registering device \"%s\"\n", ret, mitm_dev->name);
    ret = -ENODEV;
    goto register_failed;
  }

  /* Allocate the hash operations */
  /* From `hmac_sha256` at net/bluetooth/amp.c */
  hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
  if (IS_ERR(hmac_tfm)) {
    netdev_err(
        mitm_dev, "crypto_alloc_shash failed: err %ld\n", PTR_ERR(hmac_tfm));
    ret = PTR_ERR(hmac_tfm);
    goto hmac_crypto_alloc_failed;
  }

  ret = crypto_shash_setkey(hmac_tfm, hmac_key, ARRAY_SIZE(hmac_key));
  if (ret) {
    netdev_err(mitm_dev, "crypto_shash_setkey failed: err %d\n", ret);
    goto hmac_setkey_failed;
  }

#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
  proof_tfm = crypto_alloc_akcipher("pkcs1pad(rsa,sha256)", 0, 0);
  if (IS_ERR(proof_tfm)) {
    netdev_err(
        mitm_dev, "crypto_alloc_akcipher failed: err %ld\n",
        PTR_ERR(proof_tfm));
    ret = PTR_ERR(proof_tfm);
    goto proof_crypto_alloc_failed;
  }

  ret =
      crypto_akcipher_set_priv_key(proof_tfm, proof_key, ARRAY_SIZE(proof_key));
  if (ret) {
    netdev_err(mitm_dev, "crypto_akcipher_set_priv_key failed: err %d\n", ret);
    goto proof_setkey_failed;
  }

  proof_req = akcipher_request_alloc(proof_tfm, GFP_KERNEL);
  if (!proof_req) {
    netdev_err(mitm_dev, "akcipher_request_alloc failed\n");
    goto proof_alloc_req_failed;
  }

  xbuf[0] = (uint8_t *) __get_free_page(GFP_KERNEL);
  if (xbuf[0] == NULL) {
    netdev_err(mitm_dev, "__get_free_page 0 failed\n");
    goto xbuf_0_alloc_failed;
  }
  xbuf[1] = (uint8_t *) __get_free_page(GFP_KERNEL);
  if (xbuf[1] == NULL) {
    netdev_err(mitm_dev, "__get_free_page 1 failed\n");
    goto xbuf_1_alloc_failed;
  }
#else
  proof_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
  if (IS_ERR(proof_tfm)) {
    netdev_err(
        mitm_dev, "crypto_alloc_shash failed: err %ld\n", PTR_ERR(proof_tfm));
    ret = PTR_ERR(proof_tfm);
    goto proof_crypto_alloc_failed;
  }

  ret = crypto_shash_setkey(proof_tfm, proof_key, ARRAY_SIZE(proof_key));
  if (ret) {
    netdev_err(mitm_dev, "crypto_shash_setkey failed: err %d\n", ret);
    goto proof_setkey_failed;
  }
#endif /* MITM_AUTH_RSA */
#endif

#if MITM_ROLE == 1 || MITM_ROLE == 2
  hash_tfm = crypto_alloc_shash("sha256", 0, 0);
  if (IS_ERR(hash_tfm)) {
    netdev_err(
        mitm_dev, "crypto_alloc_shash failed: err %ld\n", PTR_ERR(hash_tfm));
    ret = PTR_ERR(hash_tfm);
    goto hash_crypto_alloc_failed;
  }
#endif

  debugfs_dir = debugfs_create_dir(mitm_dev->name, NULL);
  if (IS_ERR_OR_NULL(debugfs_dir)) {
    netdev_alert(
        mitm_dev, "Failed to create /sys/kernel/debug/%s\n", mitm_dev->name);
    debugfs_dir = NULL;
  } else {
    struct dentry *dentry =
        debugfs_create_file("slave", 0600, debugfs_dir, mitm_dev, &slave_fops);
    if (IS_ERR_OR_NULL(dentry)) {
      netdev_alert(
          mitm_dev, "Failed to create /sys/kernel/debug/%s/slave\n",
          mitm_dev->name);
    }
  }

  mitm = netdev_priv(mitm_dev);
  mitm->hmac_shash = hmac_tfm;
#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
  mitm->proof_akcipher = proof_tfm;
  mitm->proof_req = proof_req;
  mitm->xbuf[0] = xbuf[0];
  mitm->xbuf[1] = xbuf[1];
#else
  mitm->proof_shash = proof_tfm;
#endif /* MITM_AUTH_RSA */
#endif
#if MITM_ROLE == 1 || MITM_ROLE == 2
  mitm->hash_shash = hash_tfm;
#endif

  mitm->handle_ingress = mitm_from_slave;
  mitm->handle_egress = mitm_from_master;
#ifdef MITM_DISABLE
  // overwrite the hook APIs
  mitm->handle_ingress = mitm->handle_egress = forward;  // for measurement
#endif

#if MITM_ROLE == 1
#ifndef MITM_DOS_PROTECTION
  // initialize the hash table
  ret = mitm_skb_rht_init();
  if (ret) {
    netdev_err(mitm_dev, "mitm_skb_rht_init failed: err %d\n", ret);
    goto rht_init_failed;
  }
#endif /* MITM_DOS_PROTECTION */
#endif

#if MITM_ROLE == 1
#ifdef MITM_DOS_PROTECTION
  /* Initialize time-lock puzzle */
  time_lock_puzzle_init(mitm);
#endif /* MITM_DOS_PROTECTION */
#endif

  netdev_info(
      mitm_dev, "Initialized module with interface %s\n", mitm_dev->name);

  return 0;

#if MITM_ROLE == 1
#ifndef MITM_DOS_PROTECTION
  mitm_skb_rht_fini();
rht_init_failed:
#endif /* MITM_DOS_PROTECTION */
#endif
#if MITM_ROLE == 1 || MITM_ROLE == 2
  crypto_free_shash(hash_tfm);
hash_crypto_alloc_failed:
#endif /* MITM_ROLE == 1 || MITM_ROLE == 2 */
#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
  free_page((unsigned long) xbuf[1]);
xbuf_1_alloc_failed:
  free_page((unsigned long) xbuf[0]);
xbuf_0_alloc_failed:
  akcipher_request_free(proof_req);
proof_alloc_req_failed:
#endif /* MITM_AUTH_RSA */
proof_setkey_failed:
#ifdef MITM_AUTH_RSA
  crypto_free_akcipher(proof_tfm);
#else
  crypto_free_shash(proof_tfm);
#endif /* MITM_AUTH_RSA */

proof_crypto_alloc_failed:
#endif /* MITM_ROLE == 2 */

hmac_setkey_failed:
  crypto_free_shash(hmac_tfm);

hmac_crypto_alloc_failed:
  unregister_netdev(mitm_dev);

register_failed:
  free_netdev(mitm_dev);

  return ret;
}

void __exit mitm_exit_module(void) {
  struct mitm *mitm = netdev_priv(mitm_dev);

#if MITM_ROLE == 1
#ifdef MITM_DOS_PROTECTION
  time_lock_puzzle_exit(mitm);
#endif /* MITM_DOS_PROTECTION */
#endif

  crypto_free_shash(mitm->hmac_shash);
#if MITM_ROLE == 2
#ifdef MITM_AUTH_RSA
  crypto_free_akcipher(mitm->proof_akcipher);
  akcipher_request_free(mitm->proof_req);
  free_page((unsigned long) mitm->xbuf[0]);
  free_page((unsigned long) mitm->xbuf[1]);
#else
  crypto_free_shash(mitm->proof_shash);
#endif /* MITM_AUTH_RSA */
#endif
#if MITM_ROLE == 1 || MITM_ROLE == 2
  crypto_free_shash(mitm->hash_shash);
#endif

#if MITM_ROLE == 1
#ifndef MITM_DOS_PROTECTION
  mitm_skb_rht_fini();
#endif /* MITM_DOS_PROTECTION */
#endif

  debugfs_remove_recursive(debugfs_dir);

  rtnl_lock();
  mitm_emancipate(mitm_dev, NULL);
  rtnl_unlock();

  unregister_netdev(mitm_dev);

  /* De-initialize MPI subsystem */
  mpi_exit();

  pr_info("Exiting mitm module\n");
}

module_init(mitm_init_module);
module_exit(mitm_exit_module);

MODULE_AUTHOR("Shengtuo Hu");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_VERSION(DRV_VERSION);
