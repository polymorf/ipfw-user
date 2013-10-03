/*
 * Glue code to implement netmap I/O for the userspace version of ipfw.
 */

#include <sys/types.h>
#ifdef _KERNEL
#undef _KERNEL
#endif
/* these headers need to be compiled without _KERNEL */
//#include <sys/select.h>
//#include <sys/socket.h>
//#define __NetBSD__	// XXX conflict in bpf_filter() between pcap.h and bpf.h
//#include <netinet/in.h>

#ifdef free
/* we are built in a pseudo-kernel env so malloc and free are redefined */
#undef free
#undef malloc
#endif

#include "nm_util.h"
int verbose;

#include <stdio.h>
// #include <stdlib.h>
//#include <string.h>
#include <unistd.h>	/* read() */
#include <errno.h>	/* EINVAL */

#include <sys/malloc.h>	/* M_NOWAIT */
#include <sys/mbuf.h>	/* mbuf */
#include <net/pfil.h>	// PFIL_IN
#define _KERNEL

/* args for ipfw */
#include <netinet/ip_fw.h>
#include <netinet/ipfw/ip_fw_private.h>

/*
 * A packet comes from either a netmap slot on the source,
 * or from an mbuf that must be freed.
 * slot != NULL means a netmap slot, otherwise use buf.
 * len == 0 means an empty slot.
 */
struct txq {
	struct netmap_slot *slot;	/* can be an mbuf */
#define	TXQ_IS_SLOT	0xc555
#define	TXQ_IS_MBUF	0xaacd
	uint16_t flags;			/* 0 if slot, len if mbuf */
};

/*
 * the state associated to a netmap port:
 * (goes into the private field of my_ring)
 * XXX have an ifp at the beginning so we can use rcvif to store it.
 */
#define MY_TXQ_LEN	32
struct my_netmap_port {
	struct ifnet ifp;		/* contains if_xname */
	struct my_ring	me;
	struct my_netmap_port *peer;	/* peer port */
	struct sess	*sess;		/* my session */
	u_int		cur_txq;	/* next txq slot to use for tx */
	struct txq	q[MY_TXQ_LEN];
	/* followed by ifname */
};

/*
 * txq[] has a batch of n packets that possibly need to be forwarded.
 */
int
netmap_fwd(struct my_netmap_port *port)
{
	u_int si, i = 0;
	const u_int n = port->cur_txq;
	struct txq *x = port->q;
	int retry = 5;	/* max retries */

	if (n == 0) {
		D("nothing to forward to %s", port->ifp.if_xname);
		return 0;
	}

again:
	/* scan all rings */
        for (si = port->me.begin; i < n && si < port->me.end; si++) {
		u_int tmp;
		
		struct netmap_ring *ring = NETMAP_TXRING(port->me.nifp, si);

		prefetch(ring);
		ND("ring has %d pkts", ring->avail);
                if (ring->avail == 0)
                        continue;
                for  (; i < n && ring->avail > 0; i++) {
			struct netmap_slot *dst, *src;

			dst = &ring->slot[ring->cur];
			if (x[i].flags == TXQ_IS_SLOT) {
				src = x[i].slot;
				// XXX swap buffers
				ND("pkt %d len %d", i, src->len);
				dst->len = src->len;
				dst->flags = src->flags = NS_BUF_CHANGED;
				tmp = dst->buf_idx;
				dst->buf_idx = src->buf_idx;
				src->buf_idx = tmp;
			} else if (x[i].flags == TXQ_IS_MBUF) {
				struct mbuf *m = (void *)x[i].slot;

				ND("copy from mbuf");
				dst->len = m->__m_extlen;
				pkt_copy(m->__m_extbuf,
					NETMAP_BUF(ring, dst->buf_idx),
					dst->len);
				FREE_PKT(m);
			} else {
				panic("bad slot");
			}
			x[i].flags = 0;
			ring->cur = NETMAP_RING_NEXT(ring, ring->cur);
			ring->avail--;
		}
	}
	if (i < n) {
		if (retry-- > 0) {
			ioctl(port->me.fd, NIOCTXSYNC);
			goto again;
		}
		ND("%d buffers leftover", n - i);
		for (;i < n; i++) {
			if (x[i].flags == TXQ_IS_MBUF) {
				FREE_PKT((void *)x[i].slot);
			}
		}
	}
	port->cur_txq = 0;
	return 0;
}

void
netmap_enqueue(struct mbuf *m, int proto)
{
	struct my_netmap_port *peer = m->__m_peer;
	struct txq *x;


	if (peer == NULL) {
		D("error missing peer in %p", m);
		FREE_PKT(m);
	}
	ND("start with %d packets", peer->cur_txq);
	if (peer->cur_txq >= MY_TXQ_LEN)
		netmap_fwd(peer);
	x = peer->q + peer->cur_txq;
	x->slot = (void *)m;
	x->flags = TXQ_IS_MBUF;
	peer->cur_txq++;
	peer->sess->flags |= WANT_RUN;
	ND("end, queued %d on %s", peer->cur_txq, peer->ifname);
}

/*
 * Read packets from a port, invoke the firewall and possibly
 * pass them to the peer.
 * The firewall receives a fake mbuf on the stack that refers
 * to the netmap slot. In this case the mbuf has two extra fields,
 * indicating the original buffer and length (buf = NULL if no need
 * to copy).
 * We also need to pass the pointer to a peer, though we can use ifp for that.
 * If the result is accept, no need to copy
 * and we can just pass the slot to the destination interface.
 * Otherwise, we need to do an explicit copy.

 */
int
netmap_read(struct sess *sess, void *arg)
{
	struct my_netmap_port *port = arg;
	u_int si;
	struct mbuf dm, dm0;
	struct ip_fw_args args;
	struct my_netmap_port *peer = port->peer;
	struct txq *x = peer->q;

	bzero(&dm0, sizeof(dm0));
	bzero(&args, sizeof(args));

	/* scan all rings */
        for (si = port->me.begin; si < port->me.end; si++) {
	    struct netmap_ring *ring = NETMAP_RXRING(port->me.nifp, si);

	    prefetch(ring);
	    ND("ring has %d pkts", ring->avail);
	    if (ring->avail == 0)
		    continue;
	    prefetch(&ring->slot[ring->cur]);
	    while (ring->avail > 0) {
		u_int dst, src, idx, len;
		struct netmap_slot *slot;
		void *buf;

		dst = peer->cur_txq;
		if (dst >= MY_TXQ_LEN) {
			netmap_fwd(peer);
			continue;
		}
		src = ring->cur;
		slot = &ring->slot[src];
		prefetch (slot+1);
		idx = slot->buf_idx;
		buf = (u_char *)NETMAP_BUF(ring, idx);
		if (idx < 2) {
		    D("%s bogus RX index at offset %d",
			    port->me.nifp->ni_name, src);
		    sleep(2);
		}
		prefetch(buf);
		ring->cur = NETMAP_RING_NEXT(ring, src);
		ring->avail--;

		/* prepare to invoke the firewall */
		dm = dm0;	// XXX clear all including tags
		args.m = &dm;
		len = slot->len;
		dm.m_flags = M_STACK;
		// remember original buf and peer
		dm.__m_extbuf = buf;
		dm.__m_extlen = len;
		dm.__m_peer = peer;
		dm.__m_callback = netmap_enqueue;

		dm.m_pkthdr.rcvif = &port->ifp;
		dm.m_data = buf + 14;	// skip mac
		dm.m_len = dm.m_pkthdr.len = len - 14;
		ND("slot %d len %d", i, dm.m_len);
		// XXX ipfw_chk is slightly faster
		//ret = ipfw_chk(&args);
		ipfw_check_hook(NULL, &args.m, NULL, PFIL_IN, NULL);
		if (args.m != NULL) {	// ok. forward
			/*
			 * XXX TODO remember to clean up any tags that
			 * ipfw may have allocated
			 */
			x[dst].slot = slot;
			x[dst].flags = TXQ_IS_SLOT;
			peer->cur_txq++;
		}
		ND("exit at slot %d", next_i);
	    }
	}
	if (peer->cur_txq > 0)
		netmap_fwd(peer);
	if (port->cur_txq > 0)		// WANT_RUN
		netmap_fwd(port);
	ND("done");
	return 0;
}

/*
 * add a netmap port. We add them in pairs, so forwarding occurs
 * between two of them.
 */
void
netmap_add_port(const char *dev)
{
	static struct sess *s1 = NULL;	// XXX stateful
	struct my_netmap_port *port;
        int l;
        struct sess *s2;

        D("opening netmap device %s", dev);
        l = strlen(dev) + 1;
	if (l >= IFNAMSIZ) {
		D("name %s too long, max %d", dev, IFNAMSIZ - 1);
		sleep(2);
		return;
	}
        port = calloc(1, sizeof(*port));
        port->me.ifname = port->ifp.if_xname;
        strcpy(port->ifp.if_xname, dev);
        if (netmap_open(&port->me, 0, 0 /* promisc */)) {
                D("error opening %s", dev);
                kern_free(port);	// XXX compat
                return;
        }
        s2 = new_session(port->me.fd, netmap_read, port, WANT_READ);
	port->sess = s2;
        D("create sess %p my_netmap_port %p", s2, port);
        if (s1 == NULL) {       /* first of a pair */
                s1 = s2;
        } else {                /* second of a pair, cross link */
                struct my_netmap_port *peer = s1->arg;
                port->peer = peer;
                peer->peer = port;
                D("%p %s <-> %p %s",
                        port, port->ifp.if_xname,
                        peer, peer->ifp.if_xname);
                s1 = NULL;
        }
}
