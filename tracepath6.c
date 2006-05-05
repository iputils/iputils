/*
 * tracepath6.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <linux/types.h>
#include <linux/errqueue.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <resolv.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

int overhead = 48;
int mtu = 128000;
int hops_to = -1;
int hops_from = -1;
int no_resolve = 0;
int show_both = 0;
int mapped;

struct probehdr
{
	__u32 ttl;
	struct timeval tv;
};

void data_wait(int fd)
{
	fd_set fds;
	struct timeval tv;
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	select(fd+1, &fds, NULL, NULL, &tv);
}

int recverr(int fd, int ttl)
{
	int res;
	struct probehdr rcvbuf;
	char cbuf[512];
	struct iovec  iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct timeval tv;
	struct timeval *rettv;
	int rethops;
	int sndhops;
	int progress = -1;
	int broken_router;

restart:
	memset(&rcvbuf, -1, sizeof(rcvbuf));
	iov.iov_base = &rcvbuf;
	iov.iov_len = sizeof(rcvbuf);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	gettimeofday(&tv, NULL);
	res = recvmsg(fd, &msg, MSG_ERRQUEUE);
	if (res < 0) {
		if (errno == EAGAIN)
			return progress;
		goto restart;
	}

	progress = 2;

	rethops = -1;
	sndhops = -1;
	e = NULL;
	rettv = NULL;
	broken_router = 0;
	if (res == sizeof(rcvbuf)) {
		if (rcvbuf.ttl == 0 || rcvbuf.tv.tv_sec == 0)
			broken_router = 1;

		sndhops = rcvbuf.ttl;
		rettv = &rcvbuf.tv;
		if (sndhops != ttl)
			progress = -1;
	}
	if (sndhops>0)
		printf("%2d:  ", sndhops);
	else
		printf("%2d?: ", ttl);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IPV6) {
			switch(cmsg->cmsg_type) {
			case IPV6_RECVERR:
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
				break;
			case IPV6_HOPLIMIT:
#ifdef IPV6_2292HOPLIMIT
			case IPV6_2292HOPLIMIT:
#endif
				rethops = *(int*)CMSG_DATA(cmsg);
				break;
			}
		} else if (cmsg->cmsg_level == SOL_IP) {
			if (cmsg->cmsg_type == IP_TTL) {
				rethops = *(__u8*)CMSG_DATA(cmsg);
			}
		}
	}
	if (e == NULL) {
		printf("no info\n");
		return 0;
	}
	if (e->ee_origin == SO_EE_ORIGIN_LOCAL)
		printf("%-32s ", "[LOCALHOST]");
	else if (e->ee_origin == SO_EE_ORIGIN_ICMP6 ||
		 e->ee_origin == SO_EE_ORIGIN_ICMP) {
		struct hostent * h = NULL;
		char abuf[128];
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)(e+1);
		struct sockaddr_in *sin = (struct sockaddr_in*)(e+1);

		if (!no_resolve)
			fflush(stdout);

		if (sin->sin_family == AF_INET6) {
			inet_ntop(AF_INET6, &sin6->sin6_addr, abuf, sizeof(abuf));
			if (!no_resolve)
				h = gethostbyaddr((char *) &sin6->sin6_addr, sizeof(sin6->sin6_addr), AF_INET6);
		} else {
			inet_ntop(AF_INET, &sin->sin_addr, abuf, sizeof(abuf));
			if (!no_resolve)
				h = gethostbyaddr((char *) &sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
		}
		if (!no_resolve) {
			char fabuf[256];
			if (show_both) {
				if (h)
					snprintf(fabuf, sizeof(fabuf), "%s %s", h->h_name, abuf);
				else
					snprintf(fabuf, sizeof(fabuf), "%s", abuf);
			} else {
				snprintf(fabuf, sizeof(fabuf), "%s", h ? h->h_name : abuf);
			}
			printf("%-40s ", fabuf);
		} else {
			printf("%-32s ", abuf);
		}
	}

	if (rethops>=0) {
		if (rethops<=64)
			rethops = 65-rethops;
		else if (rethops<=128)
			rethops = 129-rethops;
		else
			rethops = 256-rethops;
		if (sndhops>=0 && rethops != sndhops)
			printf("asymm %2d ", rethops);
		else if (sndhops<0 && rethops != ttl)
			printf("asymm %2d ", rethops);
	}

	if (rettv) {
		int diff = (tv.tv_sec-rettv->tv_sec)*1000000+(tv.tv_usec-rettv->tv_usec);
		printf("%3d.%03dms ", diff/1000, diff%1000);
		if (broken_router)
			printf("(This broken router returned corrupted payload) ");
	}

	switch (e->ee_errno) {
	case ETIMEDOUT:
		printf("\n");
		break;
	case EMSGSIZE:
		printf("pmtu %d\n", e->ee_info);
		mtu = e->ee_info;
		progress = 1;
		break;
	case ECONNREFUSED:
		printf("reached\n");
		hops_to = sndhops<0 ? ttl : sndhops;
		hops_from = rethops;
		return 0;
	case EPROTO:
		printf("!P\n");
		return 0;
	case EHOSTUNREACH:
		if ((e->ee_origin == SO_EE_ORIGIN_ICMP &&
		     e->ee_type == 11 &&
		     e->ee_code == 0) ||
		    (e->ee_origin == SO_EE_ORIGIN_ICMP6 &&
		     e->ee_type == 3 &&
		     e->ee_code == 0)) {
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
		errno = e->ee_errno;
		perror("NET ERROR");
		return 0;
	}
	goto restart;
}

int probe_ttl(int fd, int ttl)
{
	int i;
	char sndbuf[mtu];
	struct probehdr *hdr = (struct probehdr*)sndbuf;

restart:

	for (i=0; i<10; i++) {
		int res;

		hdr->ttl = ttl;
		gettimeofday(&hdr->tv, NULL);
		if (send(fd, sndbuf, mtu-overhead, 0) > 0)
			break;
		res = recverr(fd, ttl);
		if (res==0)
			return 0;
		if (res > 0)
			goto restart;
	}

	if (i<10) {
		int res;

		data_wait(fd);
		if (recv(fd, sndbuf, sizeof(sndbuf), MSG_DONTWAIT) > 0) {
			printf("%2d?: reply received 8)\n", ttl);
			return 0;
		}
		res = recverr(fd, ttl);
		if (res == 1)
			goto restart;
		return res;
	}

	printf("%2d:  send failed\n", ttl);
	return 0;
}

static void usage(void) __attribute((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: tracepath6 [-n] [-b] <destination>[/<port>]\n");
	exit(-1);
}


int main(int argc, char **argv)
{
	int fd;
	int on;
	struct sockaddr_in6 sin;
	int ttl;
	char *p;
	struct addrinfo hints, *ai, *ai0;
	int ch;
	int gai;
	char pbuf[NI_MAXSERV];

	while ((ch = getopt(argc, argv, "nbh?")) != EOF) {
		switch(ch) {
		case 'n':	
			no_resolve = 1;
			break;
		case 'b':	
			show_both = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	memset(&sin, 0, sizeof(sin));
	
	p = strchr(argv[0], '/');
	if (p) {
		*p = 0;
		sprintf(pbuf, "%u", (unsigned)atoi(p+1));
	} else {
		sprintf(pbuf, "%u", (0x8000 | getpid()) & 0xffff);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = no_resolve ? AI_NUMERICHOST : 0;
	gai = getaddrinfo(argv[0], pbuf, &hints, &ai0);
	if (gai) {
		herror("getaddrinfo");	/*XXX*/
		exit(1);
	}

	fd = -1;
	for (ai = ai0; ai; ai = ai->ai_next) {
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(fd);
			fd = -1;
			continue;
		}
		memcpy(&sin, ai->ai_addr, sizeof(sin));
		break;
	}
	if (fd < 0) {
		perror("socket/connect");
		exit(1);
	}
	freeaddrinfo(ai0);

	if (!sin.sin6_addr.s6_addr32[0] && !sin.sin6_addr.s6_addr32[1]
	    && sin.sin6_addr.s6_addr32[2] == htonl(0xFFFF)) {
		mtu = 65535;
		overhead = 28;
		mapped = 1;
	}

	on = IPV6_PMTUDISC_DO;
	if (setsockopt(fd, SOL_IPV6, IPV6_MTU_DISCOVER, &on, sizeof(on))) {
		perror("IPV6_MTU_DISCOVER");
		exit(1);
	}
	if (mapped && setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on))) {
		perror("IP_MTU_DISCOVER");
		exit(1);
	}
	on = 1;
	if (setsockopt(fd, SOL_IPV6, IPV6_RECVERR, &on, sizeof(on))) {
		perror("IPV6_RECVERR");
		exit(1);
	}
	if (mapped && setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
		perror("IP_RECVERR");
		exit(1);
	}
	if (
#ifdef IPV6_RECVHOPLIMIT
	    setsockopt(fd, SOL_IPV6, IPV6_HOPLIMIT, &on, sizeof(on)) &&
	    setsockopt(fd, SOL_IPV6, IPV6_2292HOPLIMIT, &on, sizeof(on))
#else
	    setsockopt(fd, SOL_IPV6, IPV6_HOPLIMIT, &on, sizeof(on))
#endif
	    ) {
		perror("IPV6_HOPLIMIT");
		exit(1);
	}
	if (mapped && setsockopt(fd, SOL_IP, IP_RECVTTL, &on, sizeof(on))) {
		perror("IP_RECVTTL");
		exit(1);
	}

	for (ttl=1; ttl<32; ttl++) {
		int res;
		int i;

		on = ttl;
		if (setsockopt(fd, SOL_IPV6, IPV6_UNICAST_HOPS, &on, sizeof(on))) {
			perror("IPV6_UNICAST_HOPS");
			exit(1);
		}
		if (mapped && setsockopt(fd, SOL_IP, IP_TTL, &on, sizeof(on))) {
			perror("IP_TTL");
			exit(1);
		}

		for (i=0; i<3; i++) {
			res = probe_ttl(fd, ttl);
			if (res == 0)
				goto done;
			if (res > 0)
				break;
		}

		if (res < 0)
			printf("%2d:  no reply\n", ttl);
	}
	printf("     Too many hops: pmtu %d\n", mtu);

done:
	printf("     Resume: pmtu %d ", mtu);
	if (hops_to>=0)
		printf("hops %d ", hops_to);
	if (hops_from>=0)
		printf("back %d ", hops_from);
	printf("\n");
	exit(0);
}
