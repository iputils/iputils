/*
 *
 *	Modified for AF_INET6 by Pedro Roque
 *
 *	<roque@di.fc.ul.pt>
 *
 *	Original copyright notice included below
 */

/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
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
 *			P I N G . C
 *
 * Using the InterNet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 * Bugs -
 *	More statistics could always be gathered.
 *	If kernel does not support ICMP datagram sockets or
 *	if -N option is used, this program has to run SUID to ROOT or
 *	with net_cap_raw enabled.
 */

#define _GNU_SOURCE

#include <stddef.h>

#include "iputils_common.h"
#include "iputils_ni.h"
#include "ipv6.h"
#include "ping.h"

#ifndef IPV6_FLOWLABEL_MGR
# define IPV6_FLOWLABEL_MGR 32
#endif
#ifndef IPV6_FLOWINFO_SEND
# define IPV6_FLOWINFO_SEND 33
#endif

ping_func_set_st ping6_func_set = {
	.send_probe = ping6_send_probe,
	.receive_error_msg = ping6_receive_error_msg,
	.parse_reply = ping6_parse_reply,
	.install_filter = ping6_install_filter
};

#ifndef SCOPE_DELIMITER
# define SCOPE_DELIMITER '%'
#endif

int ntohsp(uint16_t *p)
{
	uint16_t v;
	memcpy(&v, p, sizeof(v));
	return ntohs(v);
}

unsigned int if_name2index(const char *ifname)
{
	unsigned int i = if_nametoindex(ifname);
	if (!i)
		error(2, 0, _("unknown iface: %s"), ifname);
	return i;
}

/* return >= 0: exit with this code, < 0: go on to next addrinfo result */
int ping6_run(struct ping_rts *rts, int argc, char **argv, struct addrinfo *ai,
	      struct socket_st *sock)
{
	int hold, packlen;
	size_t i;
	unsigned char *packet;
	char *target;
	struct icmp6_filter filter;
	int err, ret;
	static uint32_t scope_id = 0;

	if (niquery_is_enabled(&rts->ni)) {
		niquery_init_nonce(&rts->ni);

		if (!niquery_is_subject_valid(&rts->ni)) {
			rts->ni.subject = &rts->whereto6.sin6_addr;
			rts->ni.subject_len = sizeof(rts->whereto6.sin6_addr);
			rts->ni.subject_type = IPUTILS_NI_ICMP6_SUBJ_IPV6;
		}
	}

	if (argc > 1) {
		usage();
	} else if (argc == 1) {
		target = *argv;
	} else {
		if (rts->ni.query < 0 && rts->ni.subject_type != IPUTILS_NI_ICMP6_SUBJ_FQDN)
			usage();
		target = rts->ni.group;
	}

	memcpy(&rts->whereto6, ai->ai_addr, sizeof(rts->whereto6));
	rts->whereto6.sin6_port = htons(IPPROTO_ICMPV6);

	if (memchr(target, ':', strlen(target)))
		rts->opt_numeric = 1;

	if (IN6_IS_ADDR_UNSPECIFIED(&rts->firsthop.sin6_addr)) {
		memcpy(&rts->firsthop.sin6_addr, &rts->whereto6.sin6_addr, 16);
		rts->firsthop.sin6_scope_id = rts->whereto6.sin6_scope_id;
		/* Verify scope_id is the same as intermediate nodes */
		if (rts->firsthop.sin6_scope_id && scope_id && rts->firsthop.sin6_scope_id != scope_id)
			error(2, 0, _("scope discrepancy among the nodes"));
		else if (!scope_id)
			scope_id = rts->firsthop.sin6_scope_id;
	}

	rts->hostname = target;

	if (IN6_IS_ADDR_UNSPECIFIED(&rts->source6.sin6_addr)) {
		socklen_t alen;
		int probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);

		if (probe_fd < 0)
			error(2, errno, "socket");
		if (rts->device) {
			unsigned int iface = if_name2index(rts->device);
#ifdef IPV6_RECVPKTINFO
			struct in6_pktinfo ipi;

			memset(&ipi, 0, sizeof(ipi));
			ipi.ipi6_ifindex = iface;
#endif

			if (IN6_IS_ADDR_LINKLOCAL(&rts->firsthop.sin6_addr) ||
			    IN6_IS_ADDR_MC_LINKLOCAL(&rts->firsthop.sin6_addr))
				rts->firsthop.sin6_scope_id = iface;
			enable_capability_raw();
#ifdef IPV6_RECVPKTINFO
			if (setsockopt(probe_fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof ipi) == -1 ||
			    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_PKTINFO, &ipi, sizeof ipi) == -1) {
				error(2, errno, "setsockopt(IPV6_PKTINFO)");
			}
#endif
			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, rts->device, strlen(rts->device) + 1) == -1 ||
			    setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE, rts->device, strlen(rts->device) + 1) == -1) {
				error(2, errno, "setsockopt(SO_BINDTODEVICE) %s", rts->device);
			}
			disable_capability_raw();
		}

		if (rts->tclass &&
		    setsockopt(probe_fd, IPPROTO_IPV6, IPV6_TCLASS, &rts->tclass, sizeof (rts->tclass)) <0)
			error(2, errno, "setsockopt(IPV6_TCLASS)");

		if (!IN6_IS_ADDR_LINKLOCAL(&rts->firsthop.sin6_addr) &&
		    !IN6_IS_ADDR_MC_LINKLOCAL(&rts->firsthop.sin6_addr))
			rts->firsthop.sin6_family = AF_INET6;

		sock_setmark(rts, probe_fd);

		rts->firsthop.sin6_port = htons(1025);
		if (connect(probe_fd, (struct sockaddr *)&rts->firsthop, sizeof(rts->firsthop)) == -1) {
			if ((errno == EHOSTUNREACH || errno == ENETUNREACH) && ai->ai_next) {
				close(probe_fd);
				return -1;
			}
			error(2, errno, "connect");
		}
		alen = sizeof rts->source6;
		if (getsockname(probe_fd, (struct sockaddr *)&rts->source6, &alen) == -1)
			error(2, errno, "getsockname");
		rts->source6.sin6_port = 0;
		close(probe_fd);

		if (rts->device) {
			struct ifaddrs *ifa0, *ifa;

			if (getifaddrs(&ifa0))
				error(2, errno, "getifaddrs");

			for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
				if (!ifa->ifa_name || !ifa->ifa_addr ||
				    ifa->ifa_addr->sa_family != AF_INET6)
					continue;
				if (!strcmp(ifa->ifa_name, rts->device) &&
				    IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
						       &rts->source6.sin6_addr))
					break;
			}
			if (!ifa)
				error(0, 0, _("Warning: source address might be selected on device other than: %s"), rts->device);

			freeifaddrs(ifa0);
		}
	} else if (rts->device && (IN6_IS_ADDR_LINKLOCAL(&rts->source6.sin6_addr) ||
			      IN6_IS_ADDR_MC_LINKLOCAL(&rts->source6.sin6_addr)))
		rts->source6.sin6_scope_id = if_name2index(rts->device);

	if (rts->device) {
		struct cmsghdr *cmsg;
		struct in6_pktinfo *ipi;
		int rc;
		int errno_save;

		cmsg = (struct cmsghdr *)(rts->cmsgbuf + rts->cmsglen);
		rts->cmsglen += CMSG_SPACE(sizeof(*ipi));
		cmsg->cmsg_len = CMSG_LEN(sizeof(*ipi));
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;

		ipi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
		memset(ipi, 0, sizeof(*ipi));
		ipi->ipi6_ifindex = if_name2index(rts->device);

		if (rts->opt_strictsource) {
			enable_capability_raw();
			rc = setsockopt(sock->fd, SOL_SOCKET, SO_BINDTODEVICE,
					rts->device, strlen(rts->device) + 1);
			errno_save = errno;
			disable_capability_raw();

			if (rc == -1)
				error(2, errno_save, "SO_BINDTODEVICE %s", rts->device);
		}
	}

	if (IN6_IS_ADDR_MULTICAST(&rts->whereto6.sin6_addr)) {
		rts->multicast = 1;

		if (rts->uid) {
			if (rts->interval < MIN_MULTICAST_USER_INTERVAL_MS)
				error(2, 0, _("minimal interval for multicast ping for user must be >= %d ms, use -i %s (or higher)"),
					  MIN_MULTICAST_USER_INTERVAL_MS,
					  str_interval(MIN_MULTICAST_USER_INTERVAL_MS));

			if (rts->pmtudisc >= 0 && rts->pmtudisc != IPV6_PMTUDISC_DO)
				error(2, 0, _("multicast ping does not fragment"));
		}

		if (rts->pmtudisc < 0)
			rts->pmtudisc = IPV6_PMTUDISC_DO;
	}

	/* detect Subnet-Router anycast at least for the default prefix 64 */
	rts->subnet_router_anycast = 1;
	for (i = 8; i < sizeof(struct in6_addr); i++) {
		if (rts->whereto6.sin6_addr.s6_addr[i]) {
			rts->subnet_router_anycast = 0;
			break;
		}
	}

	if (rts->pmtudisc >= 0) {
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &rts->pmtudisc,
			       sizeof rts->pmtudisc) == -1)
			error(2, errno, "IPV6_MTU_DISCOVER");
	}

	int set_ident = rts->ident > 0 && sock->socktype == SOCK_DGRAM;
	if (set_ident)
		rts->source6.sin6_port = rts->ident;

	if (rts->opt_strictsource || set_ident) {
		if (bind(sock->fd, (struct sockaddr *)&rts->source6, sizeof rts->source6) == -1)
			error(2, errno, "bind icmp socket");
	}

	if ((ssize_t)rts->datalen >= (ssize_t)sizeof(struct timeval) && (rts->ni.query < 0)) {
		/* can we time transfer */
		rts->timing = 1;
	}
	packlen = rts->datalen + 8 + 4096 + 40 + 8; /* 4096 for rthdr */
	if (!(packet = (unsigned char *)malloc((unsigned int)packlen)))
		error(2, errno, _("memory allocation failed"));

	hold = 1;
	if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVERR, (const void *)&hold, sizeof hold))
		error(2, errno, "IPV6_RECVERR");

	/* Estimate memory eaten by single packet. It is rough estimate.
	 * Actually, for small datalen's it depends on kernel side a lot. */
	hold = rts->datalen + 8;
	hold += ((hold + 511) / 512) * (40 + 16 + 64 + 160);
	sock_setbufs(rts, sock, hold);

#ifdef __linux__
	if (sock->socktype == SOCK_RAW) {
		int csum_offset = 2;
		int sz_opt = sizeof(int);

		err = setsockopt(sock->fd, SOL_RAW, IPV6_CHECKSUM, &csum_offset, sz_opt);
		if (err < 0) {
			/* checksum should be enabled by default and setting this
			 * option might fail anyway.
			 */
			error(0, errno, _("setsockopt(RAW_CHECKSUM) failed - try to continue"));
		}
#else
	{
#endif

		/*
		 *	select icmp echo reply as icmp type to receive
		 */

		ICMP6_FILTER_SETBLOCKALL(&filter);

		if (niquery_is_enabled(&rts->ni))
			ICMP6_FILTER_SETPASS(IPUTILS_NI_ICMP6_REPLY, &filter);
		else
			ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);

		err = setsockopt(sock->fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof filter);

		if (err < 0)
			error(2, errno, "setsockopt(ICMP6_FILTER)");
	}

	if (rts->opt_noloop) {
		int loop = 0;
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof loop) == -1)
			error(2, errno, _("can't disable multicast loopback"));
	}
	if (rts->opt_ttl) {
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &rts->ttl,
			       sizeof rts->ttl) == -1)
			error(2, errno, _("can't set multicast hop limit"));
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &rts->ttl,
			       sizeof rts->ttl) == -1)
			error(2, errno, _("can't set unicast hop limit"));
	}

	const int on = 1;
	if (
#ifdef IPV6_RECVHOPLIMIT
	    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof on) == -1 &&
	    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &on, sizeof on) == -1
#else
	    setsockopt(sock->fd, IPPROTO_IPV6, IPV6_HOPLIMIT, &on, sizeof on) == -1
#endif
	   )
		error(2, errno, _("can't receive hop limit"));

	if (rts->opt_flowinfo) {
		char freq_buf[CMSG_ALIGN(sizeof(struct in6_flowlabel_req)) + rts->cmsglen];
		struct in6_flowlabel_req *freq = (struct in6_flowlabel_req *)freq_buf;
		int freq_len = sizeof(*freq);

		memset(freq, 0, sizeof(*freq));
		freq->flr_label = htonl(rts->flowlabel & IPV6_FLOWINFO_FLOWLABEL);
		freq->flr_action = IPV6_FL_A_GET;
		freq->flr_flags = IPV6_FL_F_CREATE;
		freq->flr_share = IPV6_FL_S_EXCL;
		memcpy(&freq->flr_dst, &rts->whereto6.sin6_addr, 16);
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, freq, freq_len) == -1)
			error(2, errno, _("can't set flowlabel"));
		rts->flowlabel = freq->flr_label;
		rts->whereto6.sin6_flowinfo = rts->flowlabel;
		if (setsockopt(sock->fd, IPPROTO_IPV6, IPV6_FLOWINFO_SEND, &on, sizeof on) == -1)
			error(2, errno, _("can't send flowinfo"));
	}

	ping_print_packet(rts);

	setup(rts, sock);

	drop_capabilities();

	ret = main_loop(rts, &ping6_func_set, sock, packet, packlen);
	free(packet);

	return ret;
}

int print_icmp(uint8_t type, uint8_t code, uint32_t info)
{
	switch (type) {
	case ICMP6_DST_UNREACH:
		printf(_("Destination unreachable: "));
		switch (code) {
		case ICMP6_DST_UNREACH_NOROUTE:
			printf(_("No route"));
			break;
		case ICMP6_DST_UNREACH_ADMIN:
			printf(_("Administratively prohibited"));
			break;
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
			printf(_("Beyond scope of source address"));
			break;
		case ICMP6_DST_UNREACH_ADDR:
			printf(_("Address unreachable"));
			break;
		case ICMP6_DST_UNREACH_NOPORT:
			printf(_("Port unreachable"));
			break;
		case ICMP6_DST_UNREACH_POLICYFAIL:
			printf(_("Source address failed ingress/egress policy"));
			break;
		case ICMP6_DST_UNREACH_REJECTROUTE:
			printf(_("Reject route to destination"));
			break;
		default:
			printf(_("Unknown code %d"), code);
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG:
		printf(_("Packet too big: mtu=%u"), info);
		if (code)
			printf(_(", code=%d"), code);
		break;
	case ICMP6_TIME_EXCEEDED:
		printf(_("Time exceeded: "));
		if (code == ICMP6_TIME_EXCEED_TRANSIT)
			printf(_("Hop limit"));
		else if (code == ICMP6_TIME_EXCEED_REASSEMBLY)
			printf(_("Defragmentation failure"));
		else
			printf(_("code %d"), code);
		break;
	case ICMP6_PARAM_PROB:
		printf(_("Parameter problem: "));
		if (code == ICMP6_PARAMPROB_HEADER)
			printf(_("Wrong header field "));
		else if (code == ICMP6_PARAMPROB_NEXTHEADER)
			printf(_("Unknown header "));
		else if (code == ICMP6_PARAMPROB_OPTION)
			printf(_("Unknown option "));
		else
			printf(_("code %d "), code);
		printf(_("at %u"), info);
		break;
	case ICMP6_ECHO_REQUEST:
		printf(_("Echo request"));
		break;
	case ICMP6_ECHO_REPLY:
		printf(_("Echo reply"));
		break;
	case MLD_LISTENER_QUERY:
		printf(_("MLD Query"));
		break;
	case MLD_LISTENER_REPORT:
		printf(_("MLD Report"));
		break;
	case MLD_LISTENER_REDUCTION:
		printf(_("MLD Reduction"));
		break;
	default:
		printf(_("unknown icmp type: %u"), type);

	}
	return 0;
}

int ping6_receive_error_msg(struct ping_rts *rts, socket_st *sock)
{
	ssize_t res;
	char cbuf[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct icmp6_hdr icmph;
	struct sockaddr_in6 target;
	int net_errors = 0;
	int local_errors = 0;
	int saved_errno = errno;

	iov.iov_base = &icmph;
	iov.iov_len = sizeof(icmph);
	msg.msg_name = (void *)&target;
	msg.msg_namelen = sizeof(target);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE | MSG_DONTWAIT);
	if (res < 0) {
		if (errno == EAGAIN || errno == EINTR)
			local_errors++;
		goto out;
	}

	e = NULL;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6) {
			if (cmsg->cmsg_type == IPV6_RECVERR)
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
		}
	}
	if (e == NULL)
		abort();

	if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
		local_errors++;
		if (rts->opt_quiet)
			goto out;
		if (rts->opt_flood)
			write_stdout("E", 1);
		else if (e->ee_errno != EMSGSIZE)
			error(0, e->ee_errno, _("local error"));
		else
			error(0, 0, _("local error: message too long, mtu: %u"), e->ee_info);
		rts->nerrors++;
	} else if (e->ee_origin == SO_EE_ORIGIN_ICMP6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(e + 1);

		if ((size_t)res < sizeof(icmph) ||
		    memcmp(&target.sin6_addr, &rts->whereto6.sin6_addr, 16) ||
		    icmph.icmp6_type != ICMP6_ECHO_REQUEST ||
		    !is_ours(rts, sock, icmph.icmp6_id)) {
			/* Not our error, not an error at all. Clear. */
			saved_errno = 0;
			goto out;
		}

		net_errors++;
		rts->nerrors++;
		if (rts->opt_quiet)
			goto out;
		if (rts->opt_flood) {
			write_stdout("\bE", 2);
		} else {
			print_timestamp(rts);
			ping_print_error_packet(rts, pr_addr(rts, sin6, sizeof *sin6), ntohs(icmph.icmp6_seq));
			print_icmp(e->ee_type, e->ee_code, e->ee_info);
			putchar('\n');
			fflush(stdout);
		}
	}

out:
	errno = saved_errno;
	return net_errors ? net_errors : -local_errors;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int build_echo(struct ping_rts *rts, uint8_t *_icmph,
	       unsigned packet_size __attribute__((__unused__)))
{
	struct icmp6_hdr *icmph;
	int cc;

	icmph = (struct icmp6_hdr *)_icmph;
	icmph->icmp6_type = ICMP6_ECHO_REQUEST;
	icmph->icmp6_code = 0;
	icmph->icmp6_cksum = 0;
	icmph->icmp6_seq = htons(rts->ntransmitted + 1);
	icmph->icmp6_id = rts->ident;

	if (rts->timing)
		gettimeofday((struct timeval *)&_icmph[8], NULL);

	cc = rts->datalen + 8;			/* skips ICMP portion */

	return cc;
}


int build_niquery(struct ping_rts *rts, uint8_t *_nih,
		  unsigned packet_size __attribute__((__unused__)))
{
	struct ni_hdr *nih;
	int cc;

	nih = (struct ni_hdr *)_nih;
	nih->ni_cksum = 0;

	nih->ni_type = IPUTILS_NI_ICMP6_QUERY;
	cc = sizeof(*nih);
	rts->datalen = 0;

	niquery_fill_nonce(&rts->ni, rts->ntransmitted + 1, nih->ni_nonce);
	nih->ni_code = rts->ni.subject_type;
	nih->ni_qtype = htons(rts->ni.query);
	nih->ni_flags = rts->ni.flag;
	memcpy(nih + 1, rts->ni.subject, rts->ni.subject_len);
	cc += rts->ni.subject_len;

	return cc;
}

int ping6_send_probe(struct ping_rts *rts, socket_st *sock, void *packet, unsigned packet_size)
{
	int len, cc;

	rcvd_clear(rts, rts->ntransmitted + 1);

	if (niquery_is_enabled(&rts->ni))
		len = build_niquery(rts, packet, packet_size);
	else
		len = build_echo(rts, packet, packet_size);

	if (rts->cmsglen == 0) {
		cc = sendto(sock->fd, (char *)packet, len, rts->confirm,
			    (struct sockaddr *)&rts->whereto6,
			    sizeof(struct sockaddr_in6));
	} else {
		struct msghdr mhdr;
		struct iovec iov;

		iov.iov_len = len;
		iov.iov_base = packet;

		memset(&mhdr, 0, sizeof(mhdr));
		mhdr.msg_name = &rts->whereto6;
		mhdr.msg_namelen = sizeof(struct sockaddr_in6);
		mhdr.msg_iov = &iov;
		mhdr.msg_iovlen = 1;
		mhdr.msg_control = rts->cmsgbuf;
		mhdr.msg_controllen = rts->cmsglen;

		cc = sendmsg(sock->fd, &mhdr, rts->confirm);
	}
	rts->confirm = 0;

	return (cc == len ? 0 : cc);
}

void pr_echo_reply(struct ping_rts *rts, uint8_t *_icmph, int cc __attribute__((__unused__)))
{
	struct icmp6_hdr *icmph = (struct icmp6_hdr *)_icmph;

	ping_print_uint(rts, _(" icmp_seq=%u"), "seq", ntohs(icmph->icmp6_seq));
}

static void putchar_safe(char c)
{
	if (isprint(c))
		putchar(c);
	else
		printf("\\%03o", c);
}

static
void pr_niquery_reply_name(struct ping_rts *rts, struct ni_hdr *nih, int len)
{
	uint8_t *h = (uint8_t *)(nih + 1);
	uint8_t *p = h + 4;
	uint8_t *end = (uint8_t *)nih + len;
	int continued = 0;
	char buf[1024];
	int ret;

	len -= sizeof(struct ni_hdr) + 4;

	if (len < 0) {
		ping_print_error_parse(rts, "too short");
		return;
	}
	while (p < end) {
		int fqdn = 1;
		size_t i;

		memset(buf, 0xff, sizeof(buf));

		if (continued)
			putchar(',');

		ret = dn_expand(h, end, p, buf, sizeof(buf));
		if (ret < 0) {
			ping_print_error_parse(rts, "truncated");
			break;
		}
		if (p + ret < end && *(p + ret) == '\0')
			fqdn = 0;

		putchar(' ');
		for (i = 0; i < strlen(buf); i++)
			putchar_safe(buf[i]);
		if (fqdn)
			putchar('.');

		p += ret + !fqdn;

		continued = 1;
	}
}

static
void pr_niquery_reply_addr(struct ping_rts *rts, struct ni_hdr *nih, int len)
{
	uint8_t *h = (uint8_t *)(nih + 1);
	uint8_t *p;
	uint8_t *end = (uint8_t *)nih + len;
	int af;
	int aflen;
	int continued = 0;
	int truncated;
	char buf[1024];

	switch (ntohs(nih->ni_qtype)) {
	case IPUTILS_NI_QTYPE_IPV4ADDR:
		af = AF_INET;
		aflen = sizeof(struct in_addr);
		truncated = nih->ni_flags & IPUTILS_NI_IPV6_FLAG_TRUNCATE;
		break;
	case IPUTILS_NI_QTYPE_IPV6ADDR:
		af = AF_INET6;
		aflen = sizeof(struct in6_addr);
		truncated = nih->ni_flags & IPUTILS_NI_IPV4_FLAG_TRUNCATE;
		break;
	default:
		/* should not happen */
		af = aflen = truncated = 0;
	}
	p = h;
	if (len < 0) {
		ping_print_error_parse(rts, "too short");
		return;
	}

	while (p < end) {
		if (continued)
			putchar(',');

		if (p + sizeof(uint32_t) + aflen > end) {
			ping_print_error_parse(rts, "truncated");
			break;
		}
		if (!inet_ntop(af, p + sizeof(uint32_t), buf, sizeof(buf)))
			printf(_(" unexpected error in inet_ntop(%s)"), strerror(errno));
		else
			printf(" %s", buf);
		p += sizeof(uint32_t) + aflen;

		continued = 1;
	}
	if (truncated)
		ping_print_truncated(rts);
}

static
void pr_niquery_reply(struct ping_rts *rts, uint8_t *_nih, int len)
{
	struct ni_hdr *nih = (struct ni_hdr *)_nih;

	switch (nih->ni_code) {
	case IPUTILS_NI_ICMP6_SUCCESS:
		switch (ntohs(nih->ni_qtype)) {
		case IPUTILS_NI_QTYPE_DNSNAME:
			pr_niquery_reply_name(rts, nih, len);
			break;
		case IPUTILS_NI_QTYPE_IPV4ADDR:
		case IPUTILS_NI_QTYPE_IPV6ADDR:
			pr_niquery_reply_addr(rts, nih, len);
			break;
		default:
			ping_print_error_qtype(rts, ntohs(nih->ni_qtype));
		}
		break;
	case IPUTILS_NI_ICMP6_REFUSED:
		printf(_(" refused"));
		break;
	case IPUTILS_NI_ICMP6_UNKNOWN:
		printf(_(" unknown"));
		break;
	default:
		printf(_(" unknown code(%02x)"), ntohs(nih->ni_code));
	}
	printf(_("; seq=%u;"), ntohsp((uint16_t *)nih->ni_nonce));
}

/*
 * parse_reply --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
int ping6_parse_reply(struct ping_rts *rts, socket_st *sock,
		      struct msghdr *msg, int cc, void *addr,
		      struct timeval *tv)
{
	struct sockaddr_in6 *from = addr;
	uint8_t *buf = msg->msg_iov->iov_base;
	struct cmsghdr *c;
	struct icmp6_hdr *icmph;
	int hops = -1;
	int wrong_source = 0;

	for (c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c)) {
		if (c->cmsg_level != IPPROTO_IPV6)
			continue;
		switch (c->cmsg_type) {
		case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
		case IPV6_2292HOPLIMIT:
#endif
			if (c->cmsg_len < CMSG_LEN(sizeof(int)))
				continue;
			memcpy(&hops, CMSG_DATA(c), sizeof(hops));
		}
	}


	/* Now the ICMP part */

	icmph = (struct icmp6_hdr *)buf;
	if (cc < 8) {
		if (rts->opt_verbose)
			ping_error(rts, 0, 0, _("packet too short: %d bytes"), cc);
		return 1;
	}

	if (icmph->icmp6_type == ICMP6_ECHO_REPLY) {
		if (!is_ours(rts, sock, icmph->icmp6_id))
			return 1;

		if (!rts->multicast && !rts->subnet_router_anycast &&
		    memcmp(&from->sin6_addr.s6_addr, &rts->whereto6.sin6_addr.s6_addr, 16))
			wrong_source = 1;

		if (gather_statistics(rts, (uint8_t *)icmph, sizeof(*icmph), cc,
				      ntohs(icmph->icmp6_seq),
				      hops, 0, tv, pr_addr(rts, from, sizeof *from),
				      pr_echo_reply,
				      rts->multicast, wrong_source)) {
			fflush(stdout);
			return 0;
		}
	} else if (icmph->icmp6_type == IPUTILS_NI_ICMP6_REPLY) {
		struct ni_hdr *nih = (struct ni_hdr *)icmph;
		int seq = niquery_check_nonce(&rts->ni, nih->ni_nonce);
		if (seq < 0)
			return 1;
		if (gather_statistics(rts, (uint8_t *)icmph, sizeof(*icmph), cc,
				      seq,
				      hops, 0, tv, pr_addr(rts, from, sizeof *from),
				      pr_niquery_reply,
				      rts->multicast, 0))
			return 0;
	} else {
		int nexthdr;
		struct ip6_hdr *iph1 = (struct ip6_hdr *)(icmph + 1);
		struct icmp6_hdr *icmph1 = (struct icmp6_hdr *)(iph1 + 1);

		/* We must not ever fall here. All the messages but
		 * echo reply are blocked by filter and error are
		 * received with IPV6_RECVERR. Ugly code is preserved
		 * however, just to remember what crap we avoided
		 * using RECVRERR. :-)
		 */

		if (cc < (int)(8 + sizeof(struct ip6_hdr) + 8))
			return 1;

		if (memcmp(&iph1->ip6_dst, &rts->whereto6.sin6_addr, 16))
			return 1;

		nexthdr = iph1->ip6_nxt;

		if (nexthdr == NEXTHDR_FRAGMENT) {
			nexthdr = *(uint8_t *)icmph1;
			icmph1++;
		}
		if (nexthdr == IPPROTO_ICMPV6) {
			if (icmph1->icmp6_type != ICMP6_ECHO_REQUEST ||
			    !is_ours(rts, sock, icmph1->icmp6_id))
				return 1;
			acknowledge(rts, ntohs(icmph1->icmp6_seq));
			return 0;
		}

		/* We've got something other than an ECHOREPLY */
		if (!rts->opt_verbose || rts->uid)
			return 1;
		print_timestamp(rts);
		printf(_("From %s: "), pr_addr(rts, from, sizeof *from));
		print_icmp(icmph->icmp6_type, icmph->icmp6_code, ntohl(icmph->icmp6_mtu));
	}

	if (rts->opt_audible) {
		putchar('\a');
		if (rts->opt_flood)
			fflush(stdout);
	}
	if (!rts->opt_flood)
		ping_finish_line(rts);
	return 0;
}

void ping6_install_filter(struct ping_rts *rts, socket_st *sock)
{
	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LD	 | BPF_H   | BPF_ABS, 4),	/* Load icmp echo ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1), /* Ours? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Yes, it passes. */
		BPF_STMT(BPF_LD  | BPF_B   | BPF_ABS, 0),	/* Load icmp type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP6_ECHO_REPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),		/* No. It passes. This must not happen. */
		BPF_STMT(BPF_RET | BPF_K, 0), 		/* Echo with wrong ident. Reject. */
	};
	static struct sock_fprog filter = {
		sizeof insns / sizeof(insns[0]),
		insns
	};

	if (once)
		return;
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(rts->ident), 0, 1);

	if (setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
		error(0, errno, _("WARNING: failed to install socket filter"));
}
