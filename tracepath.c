/*
 * tracepath.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * Keep linux/ includes after standard headers.
 * https://github.com/iputils/iputils/issues/168
 */
#include <linux/errqueue.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/types.h>

#include "iputils_common.h"

#ifdef USE_IDN
# define getnameinfo_flags	NI_IDN
#else
# define getnameinfo_flags	0
#endif

enum {
	MAX_PROBES = 10,

	MAX_HOPS_DEFAULT = 30,
	MAX_HOPS_LIMIT = 255,

	HOST_COLUMN_SIZE = 52,

	HIS_ARRAY_SIZE = 64,

	DEFAULT_OVERHEAD_IPV4 = 28,
	DEFAULT_OVERHEAD_IPV6 = 48,

	DEFAULT_MTU_IPV4 = 65535,
	DEFAULT_MTU_IPV6 = 128000,

	DEFAULT_BASEPORT = 44444,

	ANCILLARY_DATA_LEN = 512,
};

struct hhistory {
	int hops;
	struct timeval sendtime;
};

struct probehdr {
	uint32_t ttl;
	struct timeval tv;
};

struct run_state {
	struct hhistory his[HIS_ARRAY_SIZE];
	int hisptr;
	struct sockaddr_storage target;
	struct addrinfo *ai;
	int socket_fd;
	socklen_t targetlen;
	uint16_t base_port;
	uint8_t ttl;
	int max_hops;
	int overhead;
	int mtu;
	void *pktbuf;
	int hops_to;
	int hops_from;
	unsigned int
		no_resolve:1,
		show_both:1,
		mapped:1;
};

/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

static void data_wait(struct run_state const *const ctl)
{
	fd_set fds;
	struct timeval tv = {
		.tv_sec = 1,
		.tv_usec = 0
	};

	FD_ZERO(&fds);
	FD_SET(ctl->socket_fd, &fds);
	select(ctl->socket_fd + 1, &fds, NULL, NULL, &tv);
}

static void print_host(struct run_state const *const ctl, char const *const a,
		       char const *const b)
{
	int plen;

	plen = printf("%s", a);
	if (ctl->show_both)
		plen += printf(" (%s)", b);
	if (plen >= HOST_COLUMN_SIZE)
		plen = HOST_COLUMN_SIZE - 1;
	printf("%*s", HOST_COLUMN_SIZE - plen, "");
}

static int recverr(struct run_state *const ctl)
{
	ssize_t recv_size;
	struct probehdr rcvbuf;
	char cbuf[ANCILLARY_DATA_LEN];
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct sockaddr_storage addr;
	struct timeval tv;
	struct timeval *rettv;
	int slot = 0;
	int rethops;
	int sndhops;
	int progress = -1;
	int broken_router;
	char hnamebuf[NI_MAXHOST] = "";
	struct iovec iov = {
		.iov_base = &rcvbuf,
		.iov_len = sizeof(rcvbuf)
	};
	struct msghdr msg;
	const struct msghdr reset = {
		.msg_name = (uint8_t *)&addr,
		.msg_namelen = sizeof(addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
		0
	};

 restart:
	memset(&rcvbuf, -1, sizeof(rcvbuf));
	msg = reset;

	gettimeofday(&tv, NULL);
	recv_size = recvmsg(ctl->socket_fd, &msg, MSG_ERRQUEUE);
	if (recv_size < 0) {
		if (errno == EAGAIN)
			return progress;
		goto restart;
	}

	progress = ctl->mtu;

	rethops = -1;
	sndhops = -1;
	e = NULL;
	rettv = NULL;
	broken_router = 0;

	slot = -ctl->base_port;
	switch (ctl->ai->ai_family) {
	case AF_INET6:
		slot += ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
		break;
	case AF_INET:
		slot += ntohs(((struct sockaddr_in *)&addr)->sin_port);
		break;
	}

	if (slot >= 0 && slot < (HIS_ARRAY_SIZE - 1) && ctl->his[slot].hops) {
		sndhops = ctl->his[slot].hops;
		rettv = &ctl->his[slot].sendtime;
		ctl->his[slot].hops = 0;
	}
	if (recv_size == sizeof(rcvbuf)) {
		if (rcvbuf.ttl == 0 || rcvbuf.tv.tv_sec == 0)
			broken_router = 1;
		else {
			sndhops = rcvbuf.ttl;
			rettv = &rcvbuf.tv;
		}
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		switch (cmsg->cmsg_level) {
		case SOL_IPV6:
			switch (cmsg->cmsg_type) {
			case IPV6_RECVERR:
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				break;
			case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
			case IPV6_2292HOPLIMIT:
#endif
				memcpy(&rethops, CMSG_DATA(cmsg), sizeof(rethops));
				break;
			default:
				printf(_("cmsg6:%d\n "), cmsg->cmsg_type);
			}
			break;
		case SOL_IP:
			switch (cmsg->cmsg_type) {
			case IP_RECVERR:
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				break;
			case IP_TTL:
				rethops = *(uint8_t *)CMSG_DATA(cmsg);
				break;
			default:
				printf(_("cmsg4:%d\n "), cmsg->cmsg_type);
			}
		}
	}
	if (e == NULL) {
		printf(_("no info\n"));
		return 0;
	}
	if (e->ee_origin == SO_EE_ORIGIN_LOCAL)
		printf("%2d?: %-32s ", ctl->ttl, _("[LOCALHOST]"));
	else if (e->ee_origin == SO_EE_ORIGIN_ICMP6 ||
		 e->ee_origin == SO_EE_ORIGIN_ICMP) {
		char abuf[NI_MAXHOST];
		struct sockaddr *sa = (struct sockaddr *)(e + 1);
		socklen_t salen;

		if (sndhops > 0)
			printf("%2d:  ", sndhops);
		else
			printf("%2d?: ", ctl->ttl);

		switch (sa->sa_family) {
		case AF_INET6:
			salen = sizeof(struct sockaddr_in6);
			break;
		case AF_INET:
			salen = sizeof(struct sockaddr_in);
			break;
		default:
			salen = 0;
		}

		if (ctl->no_resolve || ctl->show_both) {
			if (getnameinfo(sa, salen, abuf, sizeof(abuf), NULL, 0,
					NI_NUMERICHOST))
				strcpy(abuf, "???");
		} else
			abuf[0] = 0;

		if (!ctl->no_resolve || ctl->show_both) {
			fflush(stdout);
			if (getnameinfo(sa, salen, hnamebuf, sizeof hnamebuf, NULL, 0,
					getnameinfo_flags))
				strcpy(hnamebuf, "???");
		} else
			hnamebuf[0] = 0;

		if (ctl->no_resolve)
			print_host(ctl, abuf, hnamebuf);
		else
			print_host(ctl, hnamebuf, abuf);
	}

	if (rettv) {
		struct timeval res;

		timersub(&tv, rettv, &res);
		printf(_("%3ld.%03ldms "), res.tv_sec * 1000 + res.tv_usec / 1000, res.tv_usec % 1000);
		if (broken_router)
			printf(_("(This broken router returned corrupted payload) "));
	}

	if (rethops <= 64)
		rethops = 65 - rethops;
	else if (rethops <= 128)
		rethops = 129 - rethops;
	else
		rethops = 256 - rethops;

	switch (e->ee_errno) {
	case ETIMEDOUT:
		printf("\n");
		break;
	case EMSGSIZE:
		printf(_("pmtu %d\n"), e->ee_info);
		ctl->mtu = e->ee_info;
		progress = ctl->mtu;
		break;
	case ECONNREFUSED:
		printf(_("reached\n"));
		ctl->hops_to = sndhops < 0 ? ctl->ttl : sndhops;
		ctl->hops_from = rethops;
		return 0;
	case EPROTO:
		printf("!P\n");
		return 0;
	case EHOSTUNREACH:
		if ((e->ee_origin == SO_EE_ORIGIN_ICMP &&
		     e->ee_type == ICMP_TIME_EXCEEDED &&
		     e->ee_code == ICMP_EXC_TTL) ||
		    (e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
		     e->ee_type == ICMPV6_TIME_EXCEED &&
		     e->ee_code == ICMPV6_EXC_HOPLIMIT)) {
			if (rethops >= 0) {
				if (sndhops >= 0 && rethops != sndhops)
					printf(_("asymm %2d "), rethops);
				else if (sndhops < 0 && rethops != ctl->ttl)
					printf(_("asymm %2d "), rethops);
			}
			printf("\n");
			break;
		}
		printf("!H\n");
		return 0;
	case ENETUNREACH:
		printf("!N\n");
		return 0;
	case EACCES:
		printf("!A\n");
		return 0;
	default:
		printf("\n");
		error(0, e->ee_errno, _("NET ERROR"));
		return 0;
	}
	goto restart;
}

static int probe_ttl(struct run_state *const ctl)
{
	int i;
	struct probehdr *hdr = ctl->pktbuf;

	memset(ctl->pktbuf, 0, ctl->mtu);
 restart:
	for (i = 0; i < MAX_PROBES; i++) {
		int res;

		hdr->ttl = ctl->ttl;
		switch (ctl->ai->ai_family) {
		case AF_INET6:
			((struct sockaddr_in6 *)&ctl->target)->sin6_port =
			    htons(ctl->base_port + ctl->hisptr);
			break;
		case AF_INET:
			((struct sockaddr_in *)&ctl->target)->sin_port =
			    htons(ctl->base_port + ctl->hisptr);
			break;
		}
		gettimeofday(&hdr->tv, NULL);
		ctl->his[ctl->hisptr].hops = ctl->ttl;
		ctl->his[ctl->hisptr].sendtime = hdr->tv;
		if (sendto(ctl->socket_fd, ctl->pktbuf, ctl->mtu - ctl->overhead, 0,
			   (struct sockaddr *)&ctl->target, ctl->targetlen) > 0)
			break;
		res = recverr(ctl);
		ctl->his[ctl->hisptr].hops = 0;
		if (res == 0)
			return 0;
		if (res > 0)
			goto restart;
	}
	ctl->hisptr = (ctl->hisptr + 1) & (HIS_ARRAY_SIZE - 1);

	if (i < MAX_PROBES) {
		data_wait(ctl);
		if (recv(ctl->socket_fd, ctl->pktbuf, ctl->mtu, MSG_DONTWAIT) > 0) {
			printf(_("%2d?: reply received 8)\n"), ctl->ttl);
			return 0;
		}
		return recverr(ctl);
	}

	printf(_("%2d:  send failed\n"), ctl->ttl);
	return 0;
}

static void usage(void)
{
	fprintf(stderr, _(
		"\nUsage\n"
		"  tracepath [options] <destination>\n"
		"\nOptions:\n"
		"  -4             use IPv4\n"
		"  -6             use IPv6\n"
		"  -b             print both name and ip\n"
		"  -l <length>    use packet <length>\n"
		"  -m <hops>      use maximum <hops>\n"
		"  -n             no dns name resolution\n"
		"  -p <port>      use destination <port>\n"
		"  -V             print version and exit\n"
		"  <destination>  dns name or ip address\n"
		"\nFor more details see tracepath(8).\n"));
	exit(-1);
}

int main(int argc, char **argv)
{
	struct run_state ctl = {
		.max_hops = MAX_HOPS_DEFAULT,
		.hops_to = -1,
		.hops_from = -1,
		0
	};
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_protocol = IPPROTO_UDP,
#ifdef USE_IDN
		.ai_flags = AI_IDN | AI_CANONNAME,
#endif
	};
	struct addrinfo *result;
	int ch;
	int status;
	int on;
	char *p;
	char pbuf[NI_MAXSERV];

	atexit(close_stdout);
#if defined(USE_IDN) || defined(ENABLE_NLS)
	setlocale(LC_ALL, "");
#ifdef ENABLE_NLS
	bindtextdomain (PACKAGE_NAME, LOCALEDIR);
	textdomain (PACKAGE_NAME);
#endif
#endif

	/* Support being called using `tracepath4` or `tracepath6` symlinks */
	if (argv[0][strlen(argv[0]) - 1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0]) - 1] == '6')
		hints.ai_family = AF_INET6;

	while ((ch = getopt(argc, argv, "46nbh?l:m:p:V")) != EOF) {
		switch (ch) {
		case '4':
			if (hints.ai_family == AF_INET6)
				error(2, 0, _("Only one -4 or -6 option may be specified"));
			hints.ai_family = AF_INET;
			break;
		case '6':
			if (hints.ai_family == AF_INET)
				error(2, 0, _("Only one -4 or -6 option may be specified"));
			hints.ai_family = AF_INET6;
			break;
		case 'n':
			ctl.no_resolve = 1;
			break;
		case 'b':
			ctl.show_both = 1;
			break;
		case 'l':
			ctl.mtu = strtol_or_err(optarg, _("invalid argument"), ctl.overhead, INT_MAX);
			break;
		case 'm':
			ctl.max_hops = strtol_or_err(optarg, _("invalid argument"), 0, MAX_HOPS_LIMIT);
			break;
		case 'p':
			ctl.base_port = strtol_or_err(optarg, _("invalid argument"), 0, UINT16_MAX);
			break;
		case 'V':
			printf(IPUTILS_VERSION("tracepath"));
			return 0;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* Backward compatibility */
	if (!ctl.base_port) {
		p = strchr(argv[0], '/');
		if (p) {
			*p = 0;
			ctl.base_port = strtol_or_err(p + 1, _("invalid argument"), 0, UINT16_MAX);
		} else
			ctl.base_port = DEFAULT_BASEPORT;
	}
	sprintf(pbuf, "%u", ctl.base_port);

	status = getaddrinfo(argv[0], pbuf, &hints, &result);
	if (status || !result) {
		error(1, 0, "%s: %s", argv[0], gai_strerror(status));
		abort();
	}

	for (ctl.ai = result; ctl.ai; ctl.ai = ctl.ai->ai_next) {
		if (ctl.ai->ai_family != AF_INET6 && ctl.ai->ai_family != AF_INET)
			continue;
		ctl.socket_fd = socket(ctl.ai->ai_family, ctl.ai->ai_socktype, ctl.ai->ai_protocol);
		if (ctl.socket_fd < 0)
			continue;
		memcpy(&ctl.target, ctl.ai->ai_addr, ctl.ai->ai_addrlen);
		ctl.targetlen = ctl.ai->ai_addrlen;
		break;
	}
	if (ctl.socket_fd < 0)
		error(1, errno, "socket/connect");

	switch (ctl.ai->ai_family) {
	case AF_INET6:
		ctl.overhead = DEFAULT_OVERHEAD_IPV6;
		if (!ctl.mtu)
			ctl.mtu = DEFAULT_MTU_IPV6;
		if (ctl.mtu <= ctl.overhead)
			goto pktlen_error;

		on = IPV6_PMTUDISC_DO;
		if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on)) &&
		    (on = IPV6_PMTUDISC_DO, setsockopt(ctl.socket_fd, SOL_IPV6,
		     IPV6_MTU_DISCOVER, &on, sizeof(on))))
			error(1, errno, "IPV6_MTU_DISCOVER");
		on = 1;
		if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_RECVERR, &on, sizeof(on)))
			error(1, errno, "IPV6_RECVERR");
		if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_HOPLIMIT, &on, sizeof(on))
#ifdef IPV6_RECVHOPLIMIT
		    && setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on))
#endif
		    )
			error(1, errno, "IPV6_HOPLIMIT");
		if (!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)&ctl.target)->sin6_addr)))
			break;
		ctl.mapped = 1;
		/*FALLTHROUGH*/
	case AF_INET:
		ctl.overhead = DEFAULT_OVERHEAD_IPV4;
		if (!ctl.mtu)
			ctl.mtu = DEFAULT_MTU_IPV4;
		if (ctl.mtu <= ctl.overhead)
			goto pktlen_error;

		on = IP_PMTUDISC_DO;
		if (setsockopt(ctl.socket_fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on)))
			error(1, errno, "IP_MTU_DISCOVER");
		on = 1;
		if (setsockopt(ctl.socket_fd, SOL_IP, IP_RECVERR, &on, sizeof(on)))
			error(1, errno, "IP_RECVERR");
		if (setsockopt(ctl.socket_fd, SOL_IP, IP_RECVTTL, &on, sizeof(on)))
			error(1, errno, "IP_RECVTTL");
	}

	ctl.pktbuf = malloc(ctl.mtu);
	if (!ctl.pktbuf)
		error(1, errno, "malloc");

	for (ctl.ttl = 1; ctl.ttl <= ctl.max_hops; ctl.ttl++) {
		int res = -1;
		int i;

		on = ctl.ttl;
		switch (ctl.ai->ai_family) {
		case AF_INET6:
			if (setsockopt(ctl.socket_fd, SOL_IPV6, IPV6_UNICAST_HOPS, &on, sizeof(on)))
				error(1, errno, "IPV6_UNICAST_HOPS");
			if (!ctl.mapped)
				break;
			/*FALLTHROUGH*/
		case AF_INET:
			if (setsockopt(ctl.socket_fd, SOL_IP, IP_TTL, &on, sizeof(on)))
				error(1, errno, "IP_TTL");
		}

 restart:
		for (i = 0; i < 3; i++) {
			int old_mtu;

			old_mtu = ctl.mtu;
			res = probe_ttl(&ctl);
			if (ctl.mtu != old_mtu)
				goto restart;
			if (res == 0)
				goto done;
			if (res > 0)
				break;
		}

		if (res < 0)
			printf(_("%2d:  no reply\n"), ctl.ttl);
	}
	printf("     Too many hops: pmtu %d\n", ctl.mtu);

 done:
	freeaddrinfo(result);

	printf(_("     Resume: pmtu %d "), ctl.mtu);
	if (ctl.hops_to >= 0)
		printf(_("hops %d "), ctl.hops_to);
	if (ctl.hops_from >= 0)
		printf(_("back %d "), ctl.hops_from);
	printf("\n");
	exit(0);

 pktlen_error:
	error(1, 0, _("pktlen must be within: %d < value <= %d"), ctl.overhead, INT_MAX);
}
