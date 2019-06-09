/*
 *      Modified for NRL 4.4BSD IPv6 release.
 *      07/31/96 bgp
 *
 *      Search for "#ifdef NRL" to find the changes.
 */

/*
 *	Modified for Linux IPv6 by Pedro Roque <roque@di.fc.ul.pt>
 *	31/07/1996
 *
 *	As ICMP error messages for IPv6 now include more than 8 bytes
 *	UDP datagrams are now sent via an UDP socket instead of magic
 *	RAW socket tricks.
 *
 *	Original copyright and comments left intact. They might not
 *	match the code anymore.
 */

/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Van Jacobson.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * traceroute host  - trace the route ip packets follow going to "host".
 *
 * Attempt to trace the route an ip packet would follow to some
 * internet host.  We find out intermediate hops by launching probe
 * packets with a small ttl (time to live) then listening for an
 * icmp "time exceeded" reply from a gateway.  We start our probes
 * with a ttl of one and increase by one until we get an icmp "port
 * unreachable" (which means we got to "host") or hit a max (which
 * defaults to 30 hops & can be changed with the -m flag).  Three
 * probes (change with -q flag) are sent at each ttl setting and a
 * line is printed showing the ttl, address of the gateway and
 * round trip time of each probe.  If the probe answers come from
 * different gateways, the address of each responding system will
 * be printed.  If there is no response within a 5 sec. timeout
 * interval (changed with the -w flag), a "*" is printed for that
 * probe.
 *
 * Probe packets are UDP format.  We don't want the destination
 * host to process them so the destination port is set to an
 * unlikely value (if some clod on the destination is using that
 * value, it can be changed with the -p flag).
 *
 * A sample use might be:
 *
 *     [yak 71]% traceroute nis.nsf.net.
 *     traceroute to nis.nsf.net (35.1.1.48), 30 hops max, 56 byte packet
 *      1  helios.ee.lbl.gov (128.3.112.1)  19 ms  19 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  39 ms  19 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  39 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  39 ms  40 ms  39 ms
 *      5  ccn-nerif22.Berkeley.EDU (128.32.168.22)  39 ms  39 ms  39 ms
 *      6  128.32.197.4 (128.32.197.4)  40 ms  59 ms  59 ms
 *      7  131.119.2.5 (131.119.2.5)  59 ms  59 ms  59 ms
 *      8  129.140.70.13 (129.140.70.13)  99 ms  99 ms  80 ms
 *      9  129.140.71.6 (129.140.71.6)  139 ms  239 ms  319 ms
 *     10  129.140.81.7 (129.140.81.7)  220 ms  199 ms  199 ms
 *     11  nic.merit.edu (35.1.1.48)  239 ms  239 ms  239 ms
 *
 * Note that lines 2 & 3 are the same.  This is due to a buggy
 * kernel on the 2nd hop system -- lbl-csam.arpa -- that forwards
 * packets with a zero ttl.
 *
 * A more interesting example is:
 *
 *     [yak 72]% traceroute allspice.lcs.mit.edu.
 *     traceroute to allspice.lcs.mit.edu (18.26.0.115), 30 hops max
 *      1  helios.ee.lbl.gov (128.3.112.1)  0 ms  0 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  19 ms  19 ms  19 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  19 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  19 ms  39 ms  39 ms
 *      5  ccn-nerif22.Berkeley.EDU (128.32.168.22)  20 ms  39 ms  39 ms
 *      6  128.32.197.4 (128.32.197.4)  59 ms  119 ms  39 ms
 *      7  131.119.2.5 (131.119.2.5)  59 ms  59 ms  39 ms
 *      8  129.140.70.13 (129.140.70.13)  80 ms  79 ms  99 ms
 *      9  129.140.71.6 (129.140.71.6)  139 ms  139 ms  159 ms
 *     10  129.140.81.7 (129.140.81.7)  199 ms  180 ms  300 ms
 *     11  129.140.72.17 (129.140.72.17)  300 ms  239 ms  239 ms
 *     12  * * *
 *     13  128.121.54.72 (128.121.54.72)  259 ms  499 ms  279 ms
 *     14  * * *
 *     15  * * *
 *     16  * * *
 *     17  * * *
 *     18  ALLSPICE.LCS.MIT.EDU (18.26.0.115)  339 ms  279 ms  279 ms
 *
 * (I start to see why I'm having so much trouble with mail to
 * MIT.)  Note that the gateways 12, 14, 15, 16 & 17 hops away
 * either don't send ICMP "time exceeded" messages or send them
 * with a ttl too small to reach us.  14 - 17 are running the
 * MIT C Gateway code that doesn't send "time exceeded"s.  God
 * only knows what's going on with 12.
 *
 * The silent gateway 12 in the above may be the result of a bug in
 * the 4.[23]BSD network code (and its derivatives):  4.x (x <= 3)
 * sends an unreachable message using whatever ttl remains in the
 * original datagram.  Since, for gateways, the remaining ttl is
 * zero, the icmp "time exceeded" is guaranteed to not make it back
 * to us.  The behavior of this bug is slightly more interesting
 * when it appears on the destination system:
 *
 *      1  helios.ee.lbl.gov (128.3.112.1)  0 ms  0 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  19 ms  39 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  19 ms  39 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  39 ms  40 ms  19 ms
 *      5  ccn-nerif35.Berkeley.EDU (128.32.168.35)  39 ms  39 ms  39 ms
 *      6  csgw.Berkeley.EDU (128.32.133.254)  39 ms  59 ms  39 ms
 *      7  * * *
 *      8  * * *
 *      9  * * *
 *     10  * * *
 *     11  * * *
 *     12  * * *
 *     13  rip.Berkeley.EDU (128.32.131.22)  59 ms !  39 ms !  39 ms !
 *
 * Notice that there are 12 "gateways" (13 is the final
 * destination) and exactly the last half of them are "missing".
 * What's really happening is that rip (a Sun-3 running Sun OS3.5)
 * is using the ttl from our arriving datagram as the ttl in its
 * icmp reply.  So, the reply will time out on the return path
 * (with no notice sent to anyone since icmp's aren't sent for
 * icmp's) until we probe with a ttl that's at least twice the path
 * length.  I.e., rip is really only 7 hops away.  A reply that
 * returns with a ttl of 1 is a clue this problem exists.
 * Traceroute prints a "!" after the time if the ttl is <= 1.
 * Since vendors ship a lot of obsolete (DEC's Ultrix, Sun 3.x) or
 * non-standard (HPUX) software, expect to see this problem
 * frequently and/or take care picking the target host of your
 * probes.
 *
 * Other possible annotations after the time are !H, !N, !P (got a host,
 * network or protocol unreachable, respectively), !S or !F (source
 * route failed or fragmentation needed -- neither of these should
 * ever occur and the associated gateway is busted if you see one),
 * !X (communication administratively prohibited). If
 * almost all the probes result in some kind of unreachable, traceroute
 * will give up and exit.
 *
 * Notes
 * -----
 * This program must be run by root or be setuid.  (I suggest that
 * you *don't* make it setuid -- casual use could result in a lot
 * of unnecessary traffic on our poor, congested nets.)
 *
 * This program requires a kernel mod that does not appear in any
 * system available from Berkeley:  A raw ip socket using proto
 * IPPROTO_RAW must interpret the data sent as an ip datagram (as
 * opposed to data to be wrapped in a ip datagram).  See the README
 * file that came with the source to this program for a description
 * of the mods I made to /sys/netinet/raw_ip.c.  Your mileage may
 * vary.  But, again, ANY 4.x (x < 4) BSD KERNEL WILL HAVE TO BE
 * MODIFIED TO RUN THIS PROGRAM.
 *
 * The udp port usage may appear bizarre (well, ok, it is bizarre).
 * The problem is that an icmp message only contains 8 bytes of
 * data from the original datagram.  8 bytes is the size of a udp
 * header so, if we want to associate replies with the original
 * datagram, the necessary information must be encoded into the
 * udp header (the ip id could be used but there's no way to
 * interlock with the kernel's assignment of ip id's and, anyway,
 * it would have taken a lot more kernel hacking to allow this
 * code to set the ip id).  So, to allow two or more users to
 * use traceroute simultaneously, we use this task's pid as the
 * source port (the high bit is set to move the port number out
 * of the "likely" range).  To keep track of which probe is being
 * replied to (so times and/or hop counts don't get confused by a
 * reply that was delayed in transit), we increment the destination
 * port number before each probe.
 *
 * Don't use this as a coding example.  I was trying to find a
 * routing problem and this code sort-of popped out after 48 hours
 * without sleep.  I was amazed it ever compiled, much less ran.
 *
 * I stole the idea for this program from Steve Deering.  Since
 * the first release, I've learned that had I attended the right
 * IETF working group meetings, I also could have stolen it from Guy
 * Almes or Matt Mathis.  I don't know (or care) who came up with
 * the idea first.  I envy the originators' perspicacity and I'm
 * glad they didn't keep the idea a secret.
 *
 * Tim Seaver, Ken Adelman and C. Philip Wood provided bug fixes and/or
 * enhancements to the original distribution.
 *
 * I've hacked up a round-trip-route version of this that works by
 * sending a loose-source-routed udp datagram through the destination
 * back to yourself.  Unfortunately, SO many gateways botch source
 * routing, the thing is almost worthless.  Maybe one day...
 *
 *  -- Van Jacobson (van@helios.ee.lbl.gov)
 *     Tue Dec 20 03:50:13 PST 1988
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#if __linux__
# include <endian.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#include "iputils_common.h"

#ifdef USE_IDN
# define ADDRINFO_IDN_FLAGS	AI_IDN
# define getnameinfo_flags	NI_IDN
#else
# define getnameinfo_flags	0
# define ADDRINFO_IDN_FLAGS	0
#endif

enum {
	DEFAULT_PROBES = 3,
	DEFAULT_HOPS = 30,
	DEFAULT_PORT = 32768 + 666,
	DEFAULT_WAIT = 5,
	PACKET_SIZE = 512,
	MAXPACKET = 65535,

	/*
	 * The following are copy from linux/icmpv6.h that cannot be
	 * included because icmp6_filter prototype is redefined in
	 * netinet/icmp6.h header.
	 */
	ICMPV6_DEST_UNREACH = 1,
	ICMPV6_PKT_TOOBIG = 2,
	ICMPV6_TIME_EXCEED = 3,
	ICMPV6_PARAMPROB = 4,
	ICMPV6_ECHO_REQUEST = 128,
	ICMPV6_ECHO_REPLY = 129,
	ICMPV6_MGM_QUERY = 130,
	ICMPV6_MGM_REPORT = 131,
	ICMPV6_MGM_REDUCTION = 132,
	ICMPV6_NI_QUERY = 139,
	ICMPV6_NI_REPLY = 140,
	ICMPV6_MLD2_REPORT = 143,
	ICMPV6_DHAAD_REQUEST = 144,
	ICMPV6_DHAAD_REPLY = 145,
	ICMPV6_MOBILE_PREFIX_SOL = 146,
	ICMPV6_MOBILE_PREFIX_ADV = 147,

	/*
	 * ICMP codes for neighbour discovery messages.  These are from
	 * linux kernel source include/net/ndisc.h file.  The user api
	 * includes does not have these values.
	 */
	NDISC_ROUTER_SOLICITATION = 133,
	NDISC_ROUTER_ADVERTISEMENT = 134,
	NDISC_NEIGHBOUR_SOLICITATION = 135,
	NDISC_NEIGHBOUR_ADVERTISEMENT = 136,
	NDISC_REDIRECT = 137,
};

#ifndef FD_SET
# define NFDBITS         (8 * sizeof(fd_set))
# define FD_SETSIZE      NFDBITS
# define FD_SET(n, p)    ((p)->fds_bits[(n) / NFDBITS] |= (1 << ((n) % NFDBITS)))
# define FD_CLR(n, p)    ((p)->fds_bits[(n) / NFDBITS] &= ~(1 << ((n) % NFDBITS)))
# define FD_ISSET(n, p)  ((p)->fds_bits[(n) / NFDBITS] & (1 << ((n) % NFDBITS)))
# define FD_ZERO(p)      memset((char *)(p), 0, sizeof(*(p)))
#endif

struct run_state {
	unsigned char packet[PACKET_SIZE];	/* last inbound (icmp) packet */
	int icmp_sock;			/* receive (icmp) socket file descriptor */
	int sndsock;			/* send (udp) socket file descriptor */
	char *sendbuff;
	int datalen;
	struct sockaddr_in6 whereto;	/* Who to try to reach */
	struct sockaddr_in6 saddr;
	struct sockaddr_in6 firsthop;
	char *source;
	char *device;
	char *hostname;
	long nprobes;
	int max_ttl;
	pid_t ident;
	uint16_t port;			/* start udp dest port # for probe packets */
	int options;			/* socket options */
	int waittime;			/* time to wait for response (in seconds) */
	unsigned int
		nflag:1,		/* print addresses numerically */
		verbose:1;
};

struct pkt_format {
	uint32_t ident;
	uint32_t seq;
	struct timespec ts;
};

/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

static int wait_for_reply(struct run_state *ctl, struct sockaddr_in6 *from,
			  struct in6_addr *to, const uint8_t reset_timer)
{
	fd_set fds;
	static struct timeval wait;
	ssize_t cc = 0;
	char cbuf[PACKET_SIZE];

	FD_ZERO(&fds);
	FD_SET(ctl->icmp_sock, &fds);
	if (reset_timer) {
		/*
		 * traceroute could hang if someone else has a ping
		 * running and our ICMP reply gets dropped but we don't
		 * realize it because we keep waking up to handle those
		 * other ICMP packets that keep coming in.  To fix this,
		 * "reset_timer" will only be true if the last packet that
		 * came in was for us or if this is the first time we're
		 * waiting for a reply since sending out a probe.  Note
		 * that this takes advantage of the select() feature on
		 * Linux where the remaining timeout is written to the
		 * struct timeval area.
		 */
		wait.tv_sec = ctl->waittime;
		wait.tv_usec = 0;
	}

	if (select(ctl->icmp_sock + 1, &fds, NULL, NULL, &wait) > 0) {
		struct iovec iov = {
			.iov_base = ctl->packet,
			.iov_len = sizeof(ctl->packet)
		};
		struct msghdr msg = {
			.msg_name = (void *)from,
			.msg_namelen = sizeof(*from),
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = cbuf,
			.msg_controllen = sizeof(cbuf),
			0
		};

		cc = recvmsg(ctl->icmp_sock, &msg, 0);
		if (cc >= 0) {
			struct cmsghdr *cmsg;
			struct in6_pktinfo *ipi;

			for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
				if (cmsg->cmsg_level != SOL_IPV6)
					continue;
				switch (cmsg->cmsg_type) {
				case IPV6_PKTINFO:
#ifdef IPV6_2292PKTINFO
				case IPV6_2292PKTINFO:
#endif
					ipi = (struct in6_pktinfo *)
					    CMSG_DATA(cmsg);
					memcpy(to, ipi, sizeof(*to));
				}
			}
		}
	}

	return (cc);
}

static void send_probe(struct run_state *ctl, uint32_t seq, int ttl)
{
	struct pkt_format *pkt = (struct pkt_format *)ctl->sendbuff;
	int i;

	pkt->ident = htonl(ctl->ident);
	pkt->seq = htonl(seq);
	clock_gettime(CLOCK_MONOTONIC_RAW, &pkt->ts);

	i = setsockopt(ctl->sndsock, SOL_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
	if (i < 0)
		error(1, errno, "setsockopt");

	do {
		i = sendto(ctl->sndsock, ctl->sendbuff, ctl->datalen, 0,
			   (struct sockaddr *)&ctl->whereto, sizeof(ctl->whereto));
	} while (i < 0 && errno == ECONNREFUSED);

	if (i < 0 || i != ctl->datalen) {
		if (i < 0)
			error(0, errno, "sendto");
		printf(_("traceroute: wrote %s %d chars, ret=%d\n"), ctl->hostname, ctl->datalen, i);
		fflush(stdout);
	}
}

static double deltaT(struct timespec *a, struct timespec *b)
{
	struct timespec c;
	double dt;

	if ((b->tv_nsec - a->tv_nsec) < 0) {
		c.tv_sec = b->tv_sec - a->tv_sec - 1UL;
		c.tv_nsec = b->tv_nsec - a->tv_nsec + 1000000000UL;
	} else {
		c.tv_sec = b->tv_sec - a->tv_sec;
		c.tv_nsec = b->tv_nsec - a->tv_nsec;
	}
	dt = (double)(c.tv_sec * 1000.0L) + (double)(c.tv_nsec / 1000000.0L);
	return (dt);
}

/*
 * Convert an ICMP "type" field to a printable string.
 */
static char const *pr_type(const uint8_t t)
{
	switch (t) {
		/* Unknown */
	case 0:
		return _("Error");
	case ICMPV6_DEST_UNREACH:
		return _("Destination Unreachable");
	case ICMPV6_PKT_TOOBIG:
		return _("Packet Too Big");
	case ICMPV6_TIME_EXCEED:
		return _("Time Exceeded in Transit");
	case ICMPV6_PARAMPROB:
		return _("Parameter Problem");
	case ICMPV6_ECHO_REQUEST:
		return _("Echo Request");
	case ICMPV6_ECHO_REPLY:
		return _("Echo Reply");
	case ICMPV6_MGM_QUERY:
		return _("Membership Query");
	case ICMPV6_MGM_REPORT:
		return _("Membership Report");
	case ICMPV6_MGM_REDUCTION:
		return _("Membership Reduction");
	case NDISC_ROUTER_SOLICITATION:
		return _("Router Solicitation");
	case NDISC_ROUTER_ADVERTISEMENT:
		return _("Router Advertisement");
	case NDISC_NEIGHBOUR_SOLICITATION:
		return _("Neighbor Solicitation");
	case NDISC_NEIGHBOUR_ADVERTISEMENT:
		return _("Neighbor Advertisement");
	case NDISC_REDIRECT:
		return _("Redirect");
	case ICMPV6_NI_QUERY:
		return _("Neighbor Query");
	case ICMPV6_NI_REPLY:
		return _("Neighbor Reply");
	case ICMPV6_MLD2_REPORT:
		return _("Multicast Listener Report packet");
	case ICMPV6_DHAAD_REQUEST:
		return _("Home Agent Address Discovery Request Message");
	case ICMPV6_DHAAD_REPLY:
		return _("Home Agent Address Discovery Reply message");
	case ICMPV6_MOBILE_PREFIX_SOL:
		return _("Mobile Prefix Solicitation Message");
	case ICMPV6_MOBILE_PREFIX_ADV:
		return _("Mobile Prefix Solicitation Advertisement");
	default:
		return _("OUT-OF-RANGE");
	}
	abort();
}

static int packet_ok(struct run_state *ctl, int cc, struct sockaddr_in6 *from,
		     struct in6_addr *to, uint32_t seq, struct timespec *ts)
{
	struct icmp6_hdr *icp = (struct icmp6_hdr *)ctl->packet;
	uint8_t type, code;

	type = icp->icmp6_type;
	code = icp->icmp6_code;

	if ((type == ICMP6_TIME_EXCEEDED && code == ICMP6_TIME_EXCEED_TRANSIT)
	    || type == ICMP6_DST_UNREACH) {
		struct ip6_hdr *hip;
		struct udphdr *up;
		int nexthdr;

		hip = (struct ip6_hdr *)(icp + 1);
		up = (struct udphdr *)(hip + 1);
		nexthdr = hip->ip6_nxt;

		if (nexthdr == 44) {
			nexthdr = *(unsigned char *)up;
			up++;
		}
		if (nexthdr == IPPROTO_UDP) {
			struct pkt_format *pkt;

			pkt = (struct pkt_format *)(up + 1);

			if (ntohl(pkt->ident) == (uint32_t) ctl->ident && ntohl(pkt->seq) == seq) {
				*ts = pkt->ts;
				return (type == ICMP6_TIME_EXCEEDED ? -1 : code + 1);
			}
		}

	}

	if (ctl->verbose) {
		unsigned char *p;
		char pa1[NI_MAXHOST];
		char pa2[NI_MAXHOST];
		int i;

		p = (unsigned char *)(icp + 1);

		printf("\n%d bytes from %s to %s", cc,
		       inet_ntop(AF_INET6, &from->sin6_addr, pa1, sizeof(pa1)),
		       inet_ntop(AF_INET6, to, pa2, sizeof(pa2)));

		printf(": icmp type %d (%s) code %d\n", type, pr_type(type), icp->icmp6_code);

		cc -= sizeof(struct icmp6_hdr);
		for (i = 0; i < cc; i++) {
			if (i % 16 == 0)
				printf("%04x:", i);
			if (i % 4 == 0)
				printf(" ");
			printf("%02x", 0xff & (unsigned)p[i]);
			if (i % 16 == 15 && i + 1 < cc)
				printf("\n");
		}
		printf("\n");
	}

	return (0);
}

static void print(struct run_state *ctl, struct sockaddr_in6 *from)
{
	char pa[NI_MAXHOST] = "";
	char hnamebuf[NI_MAXHOST] = "";

	if (ctl->nflag)
		printf(" %s", inet_ntop(AF_INET6, &from->sin6_addr, pa, sizeof(pa)));
	else {
		inet_ntop(AF_INET6, &from->sin6_addr, pa, sizeof(pa));
		getnameinfo((struct sockaddr *)from, sizeof *from, hnamebuf,
			    sizeof hnamebuf, NULL, 0, getnameinfo_flags);

		printf(" %s (%s)", hnamebuf[0] ? hnamebuf : pa, pa);
	}
}

static __attribute__((noreturn)) void usage(void)
{
	fprintf(stderr, _(
		"\nUsage:\n"
		"  traceroute6 [options] <destination>\n"
		"\nOptions:\n"
		"  -d            use SO_DEBUG socket option\n"
		"  -i <device>   bind to <device>\n"
		"  -m <hops>     use maximum <hops>\n"
		"  -n            no dns name resolution\n"
		"  -p <port>     use destination <port>\n"
		"  -q <nprobes>  number of probes\n"
		"  -r            use SO_DONTROUTE socket option\n"
		"  -s <address>  use source <address>\n"
		"  -v            verbose output\n"
		"  -w <timeout>  time to wait for response\n"
		"\nFor more details see traceroute6(8).\n"));
	exit(1);
}

static uint16_t get_ip_unprivileged_port_start(const uint16_t fallback)
{
	FILE *f;
	uint16_t nr = fallback;

	f = fopen("/proc/sys/net/ipv4/ip_unprivileged_port_start", "r");
	if (f) {
		if (fscanf(f, "%" SCNu16, &nr) != 1)
			nr = fallback;
		fclose(f);
	}
	return nr;
}

int main(int argc, char **argv)
{
	struct run_state ctl = {
		.nprobes = DEFAULT_PROBES,
		.max_ttl = DEFAULT_HOPS,
		.port = DEFAULT_PORT,
		.waittime = DEFAULT_WAIT,
		0
	};
	char pa[NI_MAXHOST];
	extern char *optarg;
	extern int optind;
	struct addrinfo hints6 = {
		.ai_family = AF_INET6,
		.ai_socktype = SOCK_RAW,
		.ai_flags = AI_CANONNAME | ADDRINFO_IDN_FLAGS
	};
	struct addrinfo *result;
	int status;
	struct sockaddr_in6 from;
	struct sockaddr_in6 *to = (struct sockaddr_in6 *)&ctl.whereto;
	int ch, i, ttl, on = 1;
	long probe;
	uint32_t seq = 0;
	char *resolved_hostname = NULL;

	atexit(close_stdout);
	ctl.datalen = sizeof(struct pkt_format);
	ctl.icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (ctl.icmp_sock < 0)
		error(1, errno, "icmp socket");

	if (setuid(getuid()))
		error(-1, errno, "setuid");
#ifdef HAVE_LIBCAP
	{
		cap_t caps = cap_init();

		if (cap_set_proc(caps))
			error(-1, errno, "cap_set_proc");
		cap_free(caps);
	}
#endif

#if defined(USE_IDN) || defined(ENABLE_NLS)
	setlocale(LC_ALL, "");
#ifdef ENABLE_NLS
	bindtextdomain (PACKAGE_NAME, LOCALEDIR);
	textdomain (PACKAGE_NAME);
#endif
#endif
	while ((ch = getopt(argc, argv, "dm:np:q:rs:w:vi:V")) != EOF) {
		switch (ch) {
		case 'd':
			ctl.options |= SO_DEBUG;
			break;
		case 'm':
			ctl.max_ttl = strtol_or_err(optarg, _("invalid argument"), 2, INT_MAX);
			break;
		case 'n':
			ctl.nflag = 1;
			break;
		case 'p':
			ctl.port = strtol_or_err(optarg, _("invalid argument"), 1, UINT16_MAX);
			break;
		case 'q':
			ctl.nprobes = strtol_or_err(optarg, _("invalid argument"), 1, LONG_MAX);
			break;
		case 'r':
			ctl.options |= SO_DONTROUTE;
			break;
		case 's':
			/*
			 * set the ip source address of the outbound probe
			 * (e.g., on a multi-homed host).
			 */
			ctl.source = optarg;
			break;
		case 'i':
			ctl.device = optarg;
			break;
		case 'v':
			ctl.verbose = 1;
			break;
		case 'w':
			ctl.waittime = atoi(optarg);
			if (ctl.waittime <= 1)
				error(1, 0, _("wait must be >1 sec"));
			break;
		case 'V':
			printf(IPUTILS_VERSION("traceroute6"));
			exit(0);
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	setlinebuf(stdout);

	memset((char *)&ctl.whereto, 0, sizeof(ctl.whereto));

	to->sin6_family = AF_INET6;

	if (inet_pton(AF_INET6, *argv, &to->sin6_addr) > 0) {
		ctl.hostname = *argv;
	} else {
		status = getaddrinfo(*argv, NULL, &hints6, &result);
		if (status)
			error(1, 0, "%s: %s", *argv, gai_strerror(status));
		memcpy(to, result->ai_addr, sizeof *to);
		resolved_hostname = strdup(result->ai_canonname);
		if (resolved_hostname == NULL)
			error(1, errno, "cannot allocate memory");
		ctl.hostname = resolved_hostname;
		freeaddrinfo(result);
	}

	to->sin6_port = htons(ctl.port);

	ctl.firsthop = *to;
	if (*++argv) {
		ctl.datalen = atoi(*argv);
		/*
		 * Message for rpm maintainers: have _shame_.  If you want
		 * to fix something send the patch to me for sanity
		 * checking.  "datalen" patch is a shit.
		 */
		if (ctl.datalen == 0)
			ctl.datalen = sizeof(struct pkt_format);
		else if (ctl.datalen < (int)sizeof(struct pkt_format) || ctl.datalen >= MAXPACKET)
			error(1, 0, "packet size must be %zu <= s < %d",
				    sizeof(struct pkt_format), MAXPACKET);
	}

	ctl.ident = getpid();

	ctl.sendbuff = malloc(ctl.datalen);
	if (ctl.sendbuff == NULL)
		error(1, errno, "cannot allocate memory");

#ifdef IPV6_RECVPKTINFO
	setsockopt(ctl.icmp_sock, SOL_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
	setsockopt(ctl.icmp_sock, SOL_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
#else
	setsockopt(ctl.icmp_sock, SOL_IPV6, IPV6_PKTINFO, &on, sizeof(on));
#endif

	if (ctl.options & SO_DEBUG)
		setsockopt(ctl.icmp_sock, SOL_SOCKET, SO_DEBUG, (char *)&on, sizeof(on));
	if (ctl.options & SO_DONTROUTE)
		setsockopt(ctl.icmp_sock, SOL_SOCKET, SO_DONTROUTE, (char *)&on, sizeof(on));

#ifdef __linux__
	on = 2;
	if (setsockopt(ctl.icmp_sock, SOL_RAW, IPV6_CHECKSUM, &on, sizeof(on)) < 0) {
		/*
		 * checksum should be enabled by default and setting this
		 * option might fail anyway.
		 */
		fprintf(stderr, _("setsockopt(RAW_CHECKSUM) failed - try to continue."));
	}
#endif

	if ((ctl.sndsock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
		error(5, errno, "UDP socket");
#ifdef SO_SNDBUF
	if (setsockopt(ctl.sndsock, SOL_SOCKET, SO_SNDBUF, (char *)&ctl.datalen,
		       sizeof(ctl.datalen)) < 0)
		error(6, errno, "SO_SNDBUF");
#endif				/* SO_SNDBUF */

	if (ctl.options & SO_DEBUG)
		setsockopt(ctl.sndsock, SOL_SOCKET, SO_DEBUG, (char *)&on, sizeof(on));
	if (ctl.options & SO_DONTROUTE)
		setsockopt(ctl.sndsock, SOL_SOCKET, SO_DONTROUTE, (char *)&on, sizeof(on));

	if (ctl.source == NULL) {
		socklen_t alen;
		int probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);

		if (probe_fd < 0)
			error(1, errno, "socket");
		if (ctl.device) {
			if (setsockopt
			    (probe_fd, SOL_SOCKET, SO_BINDTODEVICE, ctl.device,
			     strlen(ctl.device) + 1) == -1)
				error(0, errno, _("WARNING: interface is ignored"));
		}
		ctl.firsthop.sin6_port = htons(get_ip_unprivileged_port_start(1025));
		if (connect(probe_fd, (struct sockaddr *)&ctl.firsthop,
			    sizeof(ctl.firsthop)) == -1)
			error(1, errno, "connect");
		alen = sizeof(ctl.saddr);
		if (getsockname(probe_fd, (struct sockaddr *)&ctl.saddr, &alen) == -1)
			error(1, errno, "getsockname");
		ctl.saddr.sin6_port = 0;
		close(probe_fd);
	} else {
		memset((char *)&ctl.saddr, 0, sizeof(ctl.saddr));
		ctl.saddr.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, ctl.source, &ctl.saddr.sin6_addr) <= 0)
			error(1, 0, _("unknown addr %s"), ctl.source);
	}

	if (bind(ctl.sndsock, (struct sockaddr *)&ctl.saddr, sizeof(ctl.saddr)) < 0)
		error(1, errno, "bind sending socket");
	if (bind(ctl.icmp_sock, (struct sockaddr *)&ctl.saddr, sizeof(ctl.saddr)) < 0)
		error(1, errno, "bind icmp6 socket");

	fprintf(stderr, _("traceroute to %s (%s)"), ctl.hostname,
		inet_ntop(AF_INET6, &to->sin6_addr, pa, sizeof(pa)));

	fprintf(stderr, _(" from %s"), inet_ntop(AF_INET6, &ctl.saddr.sin6_addr, pa, sizeof(pa)));
	fprintf(stderr, _(", %d hops max, %d byte packets\n"), ctl.max_ttl, ctl.datalen);
	fflush(stderr);

	for (ttl = 1; ttl <= ctl.max_ttl; ++ttl) {
		struct in6_addr lastaddr = { {{0,}} };
		uint8_t got_there = 0;
		long unreachable = 0;

		printf("%2d ", ttl);
		for (probe = 0; probe < ctl.nprobes; ++probe) {
			ssize_t cc;
			uint8_t reset_timer = 1;
			struct timespec t1, t2;
			struct in6_addr to_addr;

			clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
			send_probe(&ctl, ++seq, ttl);
			while ((cc = wait_for_reply(&ctl, &from, &to_addr, reset_timer)) != 0) {
				clock_gettime(CLOCK_MONOTONIC_RAW, &t2);
				if ((i = packet_ok(&ctl, cc, &from, &to_addr, seq, &t1))) {
					if (memcmp(&from.sin6_addr, &lastaddr,
						   sizeof(from.sin6_addr))) {
						print(&ctl, &from);
						memcpy(&lastaddr,
						       &from.sin6_addr, sizeof(lastaddr));
					}
					printf(_("  %.4f ms"), deltaT(&t1, &t2));
					switch (i - 1) {
					case ICMP6_DST_UNREACH_NOPORT:
						got_there = 1;
						break;

					case ICMP6_DST_UNREACH_NOROUTE:
						++unreachable;
						printf(" !N");
						break;
					case ICMP6_DST_UNREACH_ADDR:
						++unreachable;
						printf(" !H");
						break;

					case ICMP6_DST_UNREACH_ADMIN:
						++unreachable;
						printf(" !X");
						break;
					}
					break;
				} else
					reset_timer = 0;
			}
			if (cc <= 0)
				printf(" *");
			fflush(stdout);
		}
		putchar('\n');
		if (got_there || (unreachable > 0 && unreachable >= ctl.nprobes - 1))
			break;
	}
	free(resolved_hostname);
	return 0;
}
