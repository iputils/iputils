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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	If kernel does not support non-raw ICMP sockets,
 *	this program has to run SUID to ROOT or with
 *	net_cap_raw enabled.
 */

#include "ping.h"

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifndef WITHOUT_IFADDRS
#include <ifaddrs.h>
#endif

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	__u32	data;
};
#endif

ping_func_set_st ping4_func_set = {
	.send_probe = ping4_send_probe,
	.receive_error_msg = ping4_receive_error_msg,
	.parse_reply = ping4_parse_reply,
	.install_filter = ping4_install_filter
};

#define	MAXIPLEN	60
#define	MAXICMPLEN	76
#define	NROUTES		9		/* number of record route slots */
#define TOS_MAX		255		/* 8-bit TOS field */

static int ts_type;
static int nroute = 0;
static __u32 route[10];

static struct sockaddr_in whereto;	/* who to ping */
static int optlen = 0;
static int settos = 0;			/* Set TOS, Precendence or other QOS options */

static int broadcast_pings = 0;

static void pr_options(unsigned char * cp, int hlen);
static void pr_iph(struct iphdr *ip);
static void usage(void) __attribute__((noreturn));
static unsigned short in_cksum(const unsigned short *addr, int len, unsigned short salt);
static void pr_icmph(__u8 type, __u8 code, __u32 info, struct icmphdr *icp);
static int parsetos(char *str);

static struct {
	struct cmsghdr cm;
	struct in_pktinfo ipi;
} cmsg = { {sizeof(struct cmsghdr) + sizeof(struct in_pktinfo), SOL_IP, IP_PKTINFO},
	   {0, }};
int cmsg_len;

static struct sockaddr_in source = { .sin_family = AF_INET };
static char *device;
static int pmtudisc = -1;

static void create_socket(socket_st *sock, int family, int socktype, int protocol, int requisite)
{
	errno = 0;

	sock->fd = socket(family, socktype, protocol);

	/* Attempt creating a raw socket when ping socket failed */
	if (sock->fd == -1 && errno != EAFNOSUPPORT && socktype == SOCK_DGRAM) {
		if (options & F_VERBOSE)
			fprintf(stderr, "ping: socket: %s, attempting raw socket...\n", strerror(errno));
		create_socket(sock, family, SOCK_RAW, protocol, requisite);
		return;
	}

	if (sock->fd == -1) {
		if (requisite || errno != EAFNOSUPPORT || options & F_VERBOSE)
			fprintf(stderr, "ping: socket: %s\n", strerror(errno));
		if (requisite)
			exit(2);
		return;
	}

	sock->socktype = socktype;
}

static void set_socket_option(socket_st *sock, int level, int optname, const void *optval, socklen_t optlen)
{
	if (sock->fd == -1)
		return;

	if (setsockopt(sock->fd, level, optname, optval, optlen) == -1) {
		fprintf(stderr, "ping: setsockopt: %s\n", strerror(errno));
		exit(2);
	}
}

int
main(int argc, char **argv)
{
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_protocol = IPPROTO_UDP, .ai_socktype = SOCK_DGRAM, .ai_flags = getaddrinfo_flags };
	struct addrinfo *result, *ai;
	int status;
	int ch;
	socket_st sock4 = { .fd = -1 };
	socket_st sock6 = { .fd = -1 };
	char *target;

	limit_capabilities();

#ifdef USE_IDN
	setlocale(LC_ALL, "");
#endif

	/* Support being called using `ping4` or `ping6` symlinks */
	if (argv[0][strlen(argv[0])-1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0])-1] == '6')
		hints.ai_family = AF_INET6;

	/* Parse command line options */
	while ((ch = getopt(argc, argv, "h?" "4bRT:" "6F:N:" "aABc:dDfi:I:l:Lm:M:nOp:qQ:rs:S:t:UvVw:W:")) != EOF) {
		switch(ch) {
		/* IPv4 specific options */
		case '4':
			if (hints.ai_family != AF_UNSPEC) {
				fprintf(stderr, "ping: Only one -4 or -6 option may be specified\n");
				exit(2);
			}
			hints.ai_family = AF_INET;
			break;
		case 'b':
			broadcast_pings = 1;
			break;
		case 'R':
			if (options & F_TIMESTAMP) {
				fprintf(stderr, "Only one of -T or -R may be used\n");
				exit(2);
			}
			options |= F_RROUTE;
			break;
		case 'T':
			if (options & F_RROUTE) {
				fprintf(stderr, "Only one of -T or -R may be used\n");
				exit(2);
			}
			options |= F_TIMESTAMP;
			if (strcmp(optarg, "tsonly") == 0)
				ts_type = IPOPT_TS_TSONLY;
			else if (strcmp(optarg, "tsandaddr") == 0)
				ts_type = IPOPT_TS_TSANDADDR;
			else if (strcmp(optarg, "tsprespec") == 0)
				ts_type = IPOPT_TS_PRESPEC;
			else {
				fprintf(stderr, "Invalid timestamp type\n");
				exit(2);
			}
			break;
		/* IPv6 specific options */
		case '6':
			if (hints.ai_family != AF_UNSPEC) {
				fprintf(stderr, "ping: Only one -4 or -6 option may be specified\n");
				exit(2);
			}
			hints.ai_family = AF_INET6;
			break;
		case 'F':
			flowlabel = hextoui(optarg);
			if (errno || (flowlabel & ~IPV6_FLOWINFO_FLOWLABEL)) {
				fprintf(stderr, "ping: Invalid flowinfo %s\n", optarg);
				exit(2);
			}
			options |= F_FLOWINFO;
			break;
		case 'N':
			if (niquery_option_handler(optarg) < 0) {
				ping6_usage(0);
				exit(2);
			}
			hints.ai_socktype = SOCK_RAW;
			break;
		/* Common options */
		case 'a':
			options |= F_AUDIBLE;
			break;
		case 'A':
			options |= F_ADAPTIVE;
			break;
		case 'B':
			options |= F_STRICTSOURCE;
			break;
		case 'c':
			npackets = atoi(optarg);
			if (npackets <= 0) {
				fprintf(stderr, "ping: bad number of packets to transmit.\n");
				exit(2);
			}
			break;
		case 'd':
			options |= F_SO_DEBUG;
			break;
		case 'D':
			options |= F_PTIMEOFDAY;
			break;
		case 'i':
		{
			double dbl;
			char *ep;

			errno = 0;
#ifdef USE_IDN
			setlocale(LC_ALL, "C");
#endif
			dbl = strtod(optarg, &ep);
#ifdef USE_IDN
			setlocale(LC_ALL, "");
#endif

			if (errno || *ep != '\0' ||
				!finite(dbl) || dbl < 0.0 || dbl >= (double)INT_MAX / 1000 - 1.0) {
				fprintf(stderr, "ping: bad timing interval\n");
				exit(2);
			}

			interval = (int)(dbl * 1000);

			options |= F_INTERVAL;
			break;
		}
		case 'I':
			/* IPv6 */
			if (strchr(optarg, ':')) {
				char *p, *addr = strdup(optarg);

				if (!addr) {
					fprintf(stderr, "ping: out of memory\n");
					exit(2);
				}

				p = strchr(addr, SCOPE_DELIMITER);
				if (p) {
					*p = '\0';
					device = optarg + (p - addr) + 1;
				}

				if (inet_pton(AF_INET6, addr, (char*)&source6.sin6_addr) <= 0) {
					fprintf(stderr, "ping: invalid source address %s\n", optarg);
					exit(2);
				}

				options |= F_STRICTSOURCE;

				free(addr);
			} else if (inet_pton(AF_INET, optarg, &source.sin_addr) > 0) {
				options |= F_STRICTSOURCE;
			} else {
				device = optarg;
			}
			break;
		case 'l':
			preload = atoi(optarg);
			if (preload <= 0) {
				fprintf(stderr, "ping: bad preload value, should be 1..%d\n", MAX_DUP_CHK);
				exit(2);
			}
			if (preload > MAX_DUP_CHK)
				preload = MAX_DUP_CHK;
			if (uid && preload > 3) {
				fprintf(stderr, "ping: cannot set preload to value > 3\n");
				exit(2);
			}
			break;
		case 'L':
			options |= F_NOLOOP;
			break;
		case 'm':
		{
			char *endp;
			mark = (int)strtoul(optarg, &endp, 10);
			if (mark < 0 || *endp != '\0') {
				fprintf(stderr, "mark cannot be negative\n");
				exit(2);
			}
			options |= F_MARK;
			break;
		}
		case 'M':
			if (strcmp(optarg, "do") == 0)
				pmtudisc = IP_PMTUDISC_DO;
			else if (strcmp(optarg, "dont") == 0)
				pmtudisc = IP_PMTUDISC_DONT;
			else if (strcmp(optarg, "want") == 0)
				pmtudisc = IP_PMTUDISC_WANT;
			else {
				fprintf(stderr, "ping: wrong value for -M: do, dont, want are valid ones.\n");
				exit(2);
			}
			break;
		case 'n':
			options |= F_NUMERIC;
			break;
		case 'O':
			options |= F_OUTSTANDING;
			break;
		case 'f':
			/* avoid `getaddrinfo()` during flood */
			options |= F_FLOOD | F_NUMERIC;
			setbuf(stdout, (char *)NULL);
			break;
		case 'p':
			options |= F_PINGFILLED;
			fill(optarg, outpack, sizeof(outpack));
			break;
		case 'q':
			options |= F_QUIET;
			break;
		case 'Q':
			/* IPv4 */
			settos = parsetos(optarg);
			/* IPv6 */
			tclass = hextoui(optarg);
			if (errno || (tclass & ~0xff)) {
				fprintf(stderr, "ping: Invalid tclass %s\n", optarg);
				exit(2);
			}
			break;
		case 'r':
			options |= F_SO_DONTROUTE;
			break;
		case 's':
			datalen = atoi(optarg);
			if (datalen < 0) {
				fprintf(stderr, "ping: illegal negative packet size %d.\n", datalen);
				exit(2);
			}
			if (datalen > MAXPACKET - 8) {
				fprintf(stderr, "ping: packet size too large: %d\n",
					datalen);
				exit(2);
			}
			break;
		case 'S':
			sndbuf = atoi(optarg);
			if (sndbuf <= 0) {
				fprintf(stderr, "ping: bad sndbuf value.\n");
				exit(2);
			}
			break;
		case 't':
			options |= F_TTL;
			ttl = atoi(optarg);
			if (ttl < 0 || ttl > 255) {
				fprintf(stderr, "ping: ttl %u out of range\n", ttl);
				exit(2);
			}
			break;
		case 'U':
			options |= F_LATENCY;
			break;
		case 'v':
			options |= F_VERBOSE;
			break;
		case 'V':
			printf("ping utility, iputils-%s\n", SNAPSHOT);
			exit(0);
		case 'w':
			deadline = atoi(optarg);
			if (deadline < 0) {
				fprintf(stderr, "ping: bad wait time.\n");
				exit(2);
			}
			break;
		case 'W':
			lingertime = atoi(optarg);
			if (lingertime < 0 || lingertime > INT_MAX/1000000) {
				fprintf(stderr, "ping: bad linger time.\n");
				exit(2);
			}
			lingertime *= 1000;
			break;
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (!argc)
		usage();

	target = argv[argc-1];

	/* Create sockets */
	enable_capability_raw();
	if (hints.ai_family != AF_INET6)
		create_socket(&sock4, AF_INET, hints.ai_socktype, IPPROTO_ICMP, hints.ai_family == AF_INET);
	if (hints.ai_family != AF_INET)
		create_socket(&sock6, AF_INET6, hints.ai_socktype, IPPROTO_ICMPV6, sock4.fd == -1);
	disable_capability_raw();

	/* Limit address family on single-protocol systems */
	if (hints.ai_family == AF_UNSPEC) {
		if (sock4.fd == -1)
			hints.ai_family = AF_INET6;
		else if (sock6.fd == -1)
			hints.ai_family = AF_INET;
	}

	/* Set socket options */
	if (settos)
		set_socket_option(&sock4, IPPROTO_IP, IP_TOS, &settos, sizeof settos);
	if (tclass)
		set_socket_option(&sock6, IPPROTO_IPV6, IPV6_TCLASS, &tclass, sizeof tclass);

	status = getaddrinfo(target, NULL, &hints, &result);
	if (status) {
		fprintf(stderr, "ping: %s: %s\n", target, gai_strerror(status));
		exit(2);
	}

	for (ai = result; ai; ai = ai->ai_next) {
		switch (ai->ai_family) {
		case AF_INET:
			status = ping4_run(argc, argv, ai, &sock4);
			break;
		case AF_INET6:
			status = ping6_run(argc, argv, ai, &sock6);
			break;
		default:
			fprintf(stderr, "ping: unknown protocol family: %d\n", ai->ai_family);
			exit(2);
		}

		if (status == 0)
			break;
	}

	freeaddrinfo(result);

	return status;
}

int ping4_run(int argc, char **argv, struct addrinfo *ai, socket_st *sock)
{
	static const struct addrinfo hints = { .ai_family = AF_INET, .ai_protocol = IPPROTO_UDP, .ai_flags = getaddrinfo_flags };
	int hold, packlen;
	unsigned char *packet;
	char *target;
	char hnamebuf[NI_MAXHOST];
	char rspace[3 + 4 * NROUTES + 1];	/* record route space */
	__u32 *tmp_rspace;

	if (argc > 1) {
		if (options & F_RROUTE)
			usage();
		else if (options & F_TIMESTAMP) {
			if (ts_type != IPOPT_TS_PRESPEC)
				usage();
			if (argc > 5)
				usage();
		} else {
			if (argc > 10)
				usage();
			options |= F_SOURCEROUTE;
		}
	}
	while (argc > 0) {
		target = *argv;

		memset((char *)&whereto, 0, sizeof(whereto));
		whereto.sin_family = AF_INET;
		if (inet_aton(target, &whereto.sin_addr) == 1) {
			hostname = target;
			if (argc == 1)
				options |= F_NUMERIC;
		} else {
			struct addrinfo *result = NULL;
			int status;

			if (argc > 1 || !ai) {
				status = getaddrinfo(target, NULL, &hints, &result);
				if (status) {
					fprintf(stderr, "ping: %s: %s\n", target, gai_strerror(status));
					exit(2);
				}
				ai = result;
			}

			memcpy(&whereto, ai->ai_addr, sizeof whereto);
			memset(hnamebuf, 0, sizeof hnamebuf);
			if (ai->ai_canonname)
				strncpy(hnamebuf, ai->ai_canonname, sizeof hnamebuf - 1);
			hostname = hnamebuf;

			if (result)
				freeaddrinfo(result);
		}
		if (argc > 1)
			route[nroute++] = whereto.sin_addr.s_addr;
		argc--;
		argv++;
	}

	if (source.sin_addr.s_addr == 0) {
		socklen_t alen;
		struct sockaddr_in dst = whereto;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			exit(2);
		}
		if (device) {
			struct ifreq ifr;
			int rc;

			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, device, IFNAMSIZ-1);

			enable_capability_raw();
			rc = setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)+1);
			disable_capability_raw();

			if (rc == -1) {
				if (IN_MULTICAST(ntohl(dst.sin_addr.s_addr))) {
					struct ip_mreqn imr;
					if (ioctl(probe_fd, SIOCGIFINDEX, &ifr) < 0) {
						fprintf(stderr, "ping: unknown iface %s\n", device);
						exit(2);
					}
					memset(&imr, 0, sizeof(imr));
					imr.imr_ifindex = ifr.ifr_ifindex;
					if (setsockopt(probe_fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr)) == -1) {
						perror("ping: IP_MULTICAST_IF");
						exit(2);
					}
				} else {
					perror("ping: SO_BINDTODEVICE");
					exit(2);
				}
			}
		}

		if (settos &&
		    setsockopt(probe_fd, IPPROTO_IP, IP_TOS, (char *)&settos, sizeof(int)) < 0)
			perror("Warning: error setting QOS sockopts");

		dst.sin_port = htons(1025);
		if (nroute)
			dst.sin_addr.s_addr = route[0];
		if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
			if (errno == EACCES) {
				if (broadcast_pings == 0) {
					fprintf(stderr, "Do you want to ping broadcast? Then -b\n");
					exit(2);
				}
				fprintf(stderr, "WARNING: pinging broadcast address\n");
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
					       &broadcast_pings, sizeof(broadcast_pings)) < 0) {
					perror ("can't set broadcasting");
					exit(2);
				}
				if (connect(probe_fd, (struct sockaddr*)&dst, sizeof(dst)) == -1) {
					perror("connect");
					exit(2);
				}
			} else {
				perror("connect");
				exit(2);
			}
		}
		alen = sizeof(source);
		if (getsockname(probe_fd, (struct sockaddr*)&source, &alen) == -1) {
			perror("getsockname");
			exit(2);
		}
		source.sin_port = 0;

#ifndef WITHOUT_IFADDRS
		if (device) {
			struct ifaddrs *ifa0, *ifa;
			int ret;

			ret = getifaddrs(&ifa0);
			if (ret) {
				fprintf(stderr, "gatifaddrs() failed.\n");
				exit(2);
			}
			for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
				if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
					continue;
				if (!strncmp(ifa->ifa_name, device, sizeof(device) - 1) &&
				    !memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					    &source.sin_addr, sizeof(source.sin_addr)))
					break;
			}
			freeifaddrs(ifa0);
			if (!ifa)
				fprintf(stderr, "ping: Warning: source address might be selected on device other than %s.\n", device);
		}
#endif
		close(probe_fd);
	} while (0);

	if (whereto.sin_addr.s_addr == 0)
		whereto.sin_addr.s_addr = source.sin_addr.s_addr;

	if (device) {
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
		if (ioctl(sock->fd, SIOCGIFINDEX, &ifr) < 0) {
			fprintf(stderr, "ping: unknown iface %s\n", device);
			exit(2);
		}
		cmsg.ipi.ipi_ifindex = ifr.ifr_ifindex;
		cmsg_len = sizeof(cmsg);
	}

	if (broadcast_pings || IN_MULTICAST(ntohl(whereto.sin_addr.s_addr))) {
		if (uid) {
			if (interval < 1000) {
				fprintf(stderr, "ping: broadcast ping with too short interval.\n");
				exit(2);
			}
			if (pmtudisc >= 0 && pmtudisc != IP_PMTUDISC_DO) {
				fprintf(stderr, "ping: broadcast ping does not fragment.\n");
				exit(2);
			}
		}
		if (pmtudisc < 0)
			pmtudisc = IP_PMTUDISC_DO;
	}

	if (pmtudisc >= 0) {
		if (setsockopt(sock->fd, SOL_IP, IP_MTU_DISCOVER, &pmtudisc, sizeof pmtudisc) == -1) {
			perror("ping: IP_MTU_DISCOVER");
			exit(2);
		}
	}

	if ((options&F_STRICTSOURCE) &&
	    bind(sock->fd, (struct sockaddr *) &source, sizeof source) == -1) {
		perror("bind");
		exit(2);
	}

	if (sock->socktype == SOCK_RAW) {
		struct icmp_filter filt;
		filt.data = ~((1<<ICMP_SOURCE_QUENCH)|
			      (1<<ICMP_DEST_UNREACH)|
			      (1<<ICMP_TIME_EXCEEDED)|
			      (1<<ICMP_PARAMETERPROB)|
			      (1<<ICMP_REDIRECT)|
			      (1<<ICMP_ECHOREPLY));
		if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == -1)
			perror("WARNING: setsockopt(ICMP_FILTER)");
	}

	hold = 1;
	if (setsockopt(sock->fd, SOL_IP, IP_RECVERR, &hold, sizeof hold))
		fprintf(stderr, "WARNING: your kernel is veeery old. No problems.\n");

	if (sock->socktype == SOCK_DGRAM) {
		if (setsockopt(sock->fd, SOL_IP, IP_RECVTTL, &hold, sizeof hold))
			perror("WARNING: setsockopt(IP_RECVTTL)");
		if (setsockopt(sock->fd, SOL_IP, IP_RETOPTS, &hold, sizeof hold))
			perror("WARNING: setsockopt(IP_RETOPTS)");
	}

	/* record route option */
	if (options & F_RROUTE) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOP;
		rspace[1+IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1+IPOPT_OLEN] = sizeof(rspace)-1;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		optlen = 40;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof rspace) < 0) {
			perror("ping: record route");
			exit(2);
		}
	}
	if (options & F_TIMESTAMP) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (ts_type==IPOPT_TS_TSONLY ? 40 : 36);
		rspace[2] = 5;
		rspace[3] = ts_type;
		if (ts_type == IPOPT_TS_PRESPEC) {
			int i;
			rspace[1] = 4+nroute*8;
			for (i=0; i<nroute; i++) {
				tmp_rspace = (__u32*)&rspace[4+i*8];
				*tmp_rspace = route[i];
			}
		}
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
				perror("ping: ts option");
				exit(2);
			}
		}
		optlen = 40;
	}
	if (options & F_SOURCEROUTE) {
		int i;
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOOP;
		rspace[1+IPOPT_OPTVAL] = (options & F_SO_DONTROUTE) ? IPOPT_SSRR
			: IPOPT_LSRR;
		rspace[1+IPOPT_OLEN] = 3 + nroute*4;
		rspace[1+IPOPT_OFFSET] = IPOPT_MINOFF;
		for (i=0; i<nroute; i++) {
			tmp_rspace = (__u32*)&rspace[4+i*4];
			*tmp_rspace = route[i];
		}

		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, 4 + nroute*4) < 0) {
			perror("ping: record route");
			exit(2);
		}
		optlen = 40;
	}

	/* Estimate memory eaten by single packet. It is rough estimate.
	 * Actually, for small datalen's it depends on kernel side a lot. */
	hold = datalen + 8;
	hold += ((hold+511)/512)*(optlen + 20 + 16 + 64 + 160);
	sock_setbufs(sock, hold);

	if (broadcast_pings) {
		if (setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &broadcast_pings, sizeof broadcast_pings) < 0) {
			perror ("ping: can't set broadcasting");
			exit(2);
		}
	}

	if (options & F_NOLOOP) {
		int loop = 0;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, 1) == -1) {
			perror ("ping: can't disable multicast loopback");
			exit(2);
		}
	}
	if (options & F_TTL) {
		int ittl = ttl;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, 1) == -1) {
			perror ("ping: can't set multicast time-to-live");
			exit(2);
		}
		if (setsockopt(sock->fd, IPPROTO_IP, IP_TTL, &ittl, sizeof ittl) == -1) {
			perror ("ping: can't set unicast time-to-live");
			exit(2);
		}
	}

	if (datalen > 0xFFFF - 8 - optlen - 20) {
		fprintf(stderr, "Error: packet size %d is too large. Maximum is %d\n", datalen, 0xFFFF-8-20-optlen);
		exit(2);
	}

	if (datalen >= sizeof(struct timeval))	/* can we time transfer */
		timing = 1;
	packlen = datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (unsigned char *)malloc((unsigned int)packlen))) {
		fprintf(stderr, "ping: out of memory.\n");
		exit(2);
	}

	printf("PING %s (%s) ", hostname, inet_ntoa(whereto.sin_addr));
	if (device || (options&F_STRICTSOURCE))
		printf("from %s %s: ", inet_ntoa(source.sin_addr), device ?: "");
	printf("%d(%d) bytes of data.\n", datalen, datalen+8+optlen+20);

	setup(sock);

	main_loop(&ping4_func_set, sock, packet, packlen);
}


int ping4_receive_error_msg(socket_st *sock)
{
	int res;
	char cbuf[512];
	struct iovec  iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in target;
	int net_errors = 0;
	int local_errors = 0;
	int saved_errno = errno;

	iov.iov_base = &icmph;
	iov.iov_len = sizeof(icmph);
	msg.msg_name = (void*)&target;
	msg.msg_namelen = sizeof(target);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	res = recvmsg(sock->fd, &msg, MSG_ERRQUEUE|MSG_DONTWAIT);
	if (res < 0)
		goto out;

	e = NULL;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_IP) {
			if (cmsg->cmsg_type == IP_RECVERR)
				e = (struct sock_extended_err *)CMSG_DATA(cmsg);
		}
	}
	if (e == NULL)
		abort();

	if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
		local_errors++;
		if (options & F_QUIET)
			goto out;
		if (options & F_FLOOD)
			write_stdout("E", 1);
		else if (e->ee_errno != EMSGSIZE)
			fprintf(stderr, "ping: local error: %s\n", strerror(e->ee_errno));
		else
			fprintf(stderr, "ping: local error: Message too long, mtu=%u\n", e->ee_info);
		nerrors++;
	} else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
		struct sockaddr_in *sin = (struct sockaddr_in*)(e+1);

		if (res < sizeof(icmph) ||
		    target.sin_addr.s_addr != whereto.sin_addr.s_addr ||
		    icmph.type != ICMP_ECHO ||
		    !is_ours(sock, icmph.un.echo.id)) {
			/* Not our error, not an error at all. Clear. */
			saved_errno = 0;
			goto out;
		}

		acknowledge(ntohs(icmph.un.echo.sequence));

		if (sock->socktype == SOCK_RAW && !sock->working_recverr) {
			struct icmp_filter filt;
			sock->working_recverr = 1;
			/* OK, it works. Add stronger filter. */
			filt.data = ~((1<<ICMP_SOURCE_QUENCH)|  
					(1<<ICMP_REDIRECT)|
					(1<<ICMP_ECHOREPLY));
			if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, (char*)&filt, sizeof(filt)) == -1)
				perror("\rWARNING: setsockopt(ICMP_FILTER)");
		}

		net_errors++;
		nerrors++;
		if (options & F_QUIET)
			goto out;
		if (options & F_FLOOD) {
			write_stdout("\bE", 2);
		} else {
			print_timestamp();
			printf("From %s icmp_seq=%u ", pr_addr(sin, sizeof *sin), ntohs(icmph.un.echo.sequence));
			pr_icmph(e->ee_type, e->ee_code, e->ee_info, NULL);
			fflush(stdout);
		}
	}

out:
	errno = saved_errno;
	return net_errors ? : -local_errors;
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int ping4_send_probe(socket_st *sock, void *packet, unsigned packet_size)
{
	struct icmphdr *icp;
	int cc;
	int i;

	icp = (struct icmphdr *)packet;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(ntransmitted+1);
	icp->un.echo.id = ident;			/* ID */

	rcvd_clear(ntransmitted+1);

	if (timing) {
		if (options&F_LATENCY) {
			struct timeval tmp_tv;
			gettimeofday(&tmp_tv, NULL);
			memcpy(icp+1, &tmp_tv, sizeof(tmp_tv));
		} else {
			memset(icp+1, 0, sizeof(struct timeval));
		}
	}

	cc = datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((unsigned short *)icp, cc, 0);

	if (timing && !(options&F_LATENCY)) {
		struct timeval tmp_tv;
		gettimeofday(&tmp_tv, NULL);
		memcpy(icp+1, &tmp_tv, sizeof(tmp_tv));
		icp->checksum = in_cksum((unsigned short *)&tmp_tv, sizeof(tmp_tv), ~icp->checksum);
	}

	i = sendto(sock->fd, icp, cc, 0, (struct sockaddr*)&whereto, sizeof(whereto));

	return (cc == i ? 0 : i);
}

/*
 * parse_reply --
 *	Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
static
void pr_echo_reply(__u8 *_icp, int len)
{
	struct icmphdr *icp = (struct icmphdr *)_icp;
	printf(" icmp_seq=%u", ntohs(icp->un.echo.sequence));
}

int
ping4_parse_reply(struct socket_st *sock, struct msghdr *msg, int cc, void *addr, struct timeval *tv)
{
	struct sockaddr_in *from = addr;
	__u8 *buf = msg->msg_iov->iov_base;
	struct icmphdr *icp;
	struct iphdr *ip;
	int hlen;
	int csfailed;
	struct cmsghdr *cmsg;
	int ttl;
	__u8 *opts, *tmp_ttl;
	int optlen;

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	if (sock->socktype == SOCK_RAW) {
		hlen = ip->ihl*4;
		if (cc < hlen + 8 || ip->ihl < 5) {
			if (options & F_VERBOSE)
				fprintf(stderr, "ping: packet too short (%d bytes) from %s\n", cc,
					pr_addr(from, sizeof *from));
			return 1;
		}
		ttl = ip->ttl;
		opts = buf + sizeof(struct iphdr);
		optlen = hlen - sizeof(struct iphdr);
	} else {
		hlen = 0;
		ttl = 0;
		opts = buf;
		optlen = 0;
		for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if (cmsg->cmsg_level != SOL_IP)
				continue;
			if (cmsg->cmsg_type == IP_TTL) {
				if (cmsg->cmsg_len < sizeof(int))
					continue;
				tmp_ttl = (__u8 *) CMSG_DATA(cmsg);
				ttl = (int)*tmp_ttl;
			} else if (cmsg->cmsg_type == IP_RETOPTS) {
				opts = (__u8 *) CMSG_DATA(cmsg);
				optlen = cmsg->cmsg_len;
			}
		}
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((unsigned short *)icp, cc, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		if (!is_ours(sock, icp->un.echo.id))
			return 1;			/* 'Twas not our ECHO */
		if (gather_statistics((__u8*)icp, sizeof(*icp), cc,
				      ntohs(icp->un.echo.sequence),
				      ttl, 0, tv, pr_addr(from, sizeof *from),
				      pr_echo_reply)) {
			fflush(stdout);
			return 0;
		}
	} else {
		/* We fall here when a redirect or source quench arrived. */

		switch (icp->type) {
		case ICMP_ECHO:
			/* MUST NOT */
			return 1;
		case ICMP_SOURCE_QUENCH:
		case ICMP_REDIRECT:
		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
		case ICMP_PARAMETERPROB:
			{
				struct iphdr * iph = (struct  iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr*)((unsigned char *)iph + iph->ihl*4);
				int error_pkt;
				if (cc < 8+sizeof(struct iphdr)+8 ||
				    cc < 8+iph->ihl*4+8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != whereto.sin_addr.s_addr ||
				    !is_ours(sock, icp1->un.echo.id))
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				if (error_pkt) {
					acknowledge(ntohs(icp1->un.echo.sequence));
					return 0;
				}
				if (options & (F_QUIET | F_FLOOD))
					return 1;
				print_timestamp();
				printf("From %s: icmp_seq=%u ",
				       pr_addr(from, sizeof *from),
				       ntohs(icp1->un.echo.sequence));
				if (csfailed)
					printf("(BAD CHECKSUM)");
				pr_icmph(icp->type, icp->code, ntohl(icp->un.gateway), icp);
				return 1;
			}
		default:
			/* MUST NOT */
			break;
		}
		if ((options & F_FLOOD) && !(options & (F_VERBOSE|F_QUIET))) {
			if (!csfailed)
				write_stdout("!E", 2);
			else
				write_stdout("!EC", 3);
			return 0;
		}
		if (!(options & F_VERBOSE) || uid)
			return 0;
		if (options & F_PTIMEOFDAY) {
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}
		printf("From %s: ", pr_addr(from, sizeof *from));
		if (csfailed) {
			printf("(BAD CHECKSUM)\n");
			return 0;
		}
		pr_icmph(icp->type, icp->code, ntohl(icp->un.gateway), icp);
		return 0;
	}

	if (options & F_AUDIBLE) {
		putchar('\a');
		if(options & F_FLOOD)
			fflush(stdout);
	}
	if (!(options & F_FLOOD)) {
		pr_options(opts, optlen + sizeof(struct iphdr));

		putchar('\n');
		fflush(stdout);
	}
	return 0;
}


#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short
in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
void pr_icmph(__u8 type, __u8 code, __u32 info, struct icmphdr *icp)
{
	switch(type) {
	case ICMP_ECHOREPLY:
		printf("Echo Reply\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch(code) {
		case ICMP_NET_UNREACH:
			printf("Destination Net Unreachable\n");
			break;
		case ICMP_HOST_UNREACH:
			printf("Destination Host Unreachable\n");
			break;
		case ICMP_PROT_UNREACH:
			printf("Destination Protocol Unreachable\n");
			break;
		case ICMP_PORT_UNREACH:
			printf("Destination Port Unreachable\n");
			break;
		case ICMP_FRAG_NEEDED:
			printf("Frag needed and DF set (mtu = %u)\n", info);
			break;
		case ICMP_SR_FAILED:
			printf("Source Route Failed\n");
			break;
		case ICMP_NET_UNKNOWN:
			printf("Destination Net Unknown\n");
			break;
		case ICMP_HOST_UNKNOWN:
			printf("Destination Host Unknown\n");
			break;
		case ICMP_HOST_ISOLATED:
			printf("Source Host Isolated\n");
			break;
		case ICMP_NET_ANO:
			printf("Destination Net Prohibited\n");
			break;
		case ICMP_HOST_ANO:
			printf("Destination Host Prohibited\n");
			break;
		case ICMP_NET_UNR_TOS:
			printf("Destination Net Unreachable for Type of Service\n");
			break;
		case ICMP_HOST_UNR_TOS:
			printf("Destination Host Unreachable for Type of Service\n");
			break;
		case ICMP_PKT_FILTERED:
			printf("Packet filtered\n");
			break;
		case ICMP_PREC_VIOLATION:
			printf("Precedence Violation\n");
			break;
		case ICMP_PREC_CUTOFF:
			printf("Precedence Cutoff\n");
			break;
		default:
			printf("Dest Unreachable, Bad Code: %d\n", code);
			break;
		}
		if (icp && (options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1));
		break;
	case ICMP_SOURCE_QUENCH:
		printf("Source Quench\n");
		if (icp && (options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1));
		break;
	case ICMP_REDIRECT:
		switch(code) {
		case ICMP_REDIR_NET:
			printf("Redirect Network");
			break;
		case ICMP_REDIR_HOST:
			printf("Redirect Host");
			break;
		case ICMP_REDIR_NETTOS:
			printf("Redirect Type of Service and Network");
			break;
		case ICMP_REDIR_HOSTTOS:
			printf("Redirect Type of Service and Host");
			break;
		default:
			printf("Redirect, Bad Code: %d", code);
			break;
		}
		{
			struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr =  { icp ? icp->un.gateway : info } };

			printf("(New nexthop: %s)\n", pr_addr(&sin, sizeof sin));
		}
		if (icp && (options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1));
		break;
	case ICMP_ECHO:
		printf("Echo Request\n");
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			printf("Time to live exceeded\n");
			break;
		case ICMP_EXC_FRAGTIME:
			printf("Frag reassembly time exceeded\n");
			break;
		default:
			printf("Time exceeded, Bad Code: %d\n", code);
			break;
		}
		if (icp && (options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1));
		break;
	case ICMP_PARAMETERPROB:
		printf("Parameter problem: pointer = %u\n", icp ? (ntohl(icp->un.gateway)>>24) : info);
		if (icp && (options & F_VERBOSE))
			pr_iph((struct iphdr*)(icp + 1));
		break;
	case ICMP_TIMESTAMP:
		printf("Timestamp\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		printf("Timestamp Reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		printf("Information Request\n");
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		printf("Information Reply\n");
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		printf("Address Mask Request\n");
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		printf("Address Mask Reply\n");
		break;
#endif
	default:
		printf("Bad ICMP type: %d\n", type);
	}
}

void pr_options(unsigned char * cp, int hlen)
{
	int i, j;
	int optlen, totlen;
	unsigned char * optptr;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	totlen = hlen-sizeof(struct iphdr);
	optptr = cp;

	while (totlen > 0) {
		if (*optptr == IPOPT_EOL)
			break;
		if (*optptr == IPOPT_NOP) {
			totlen--;
			optptr++;
			printf("\nNOP");
			continue;
		}
		cp = optptr;
		optlen = optptr[1];
		if (optlen < 2 || optlen > totlen)
			break;

		switch (*cp) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			printf("\n%cSRR: ", *cp==IPOPT_SSRR ? 'S' : 'L');
			j = *++cp;
			i = *++cp;
			i -= 4;
			cp++;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

						printf("\t%s", pr_addr(&sin, sizeof sin));
					}
					j -= 4;
					putchar('\n');
					if (j <= IPOPT_MINOFF)
						break;
				}
			}
			break;
		case IPOPT_RR:
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= IPOPT_MINOFF;
			if (i <= 0)
				break;
			if (i == old_rrlen
			    && !memcmp(cp, old_rr, i)
			    && !(options & F_FLOOD)) {
				printf("\t(same route)");
				i = ((i + 3) / 4) * 4;
				cp += i;
				break;
			}
			old_rrlen = i;
			memcpy(old_rr, (char *)cp, i);
			printf("\nRR: ");
			cp++;
			for (;;) {
				__u32 address;
				memcpy(&address, cp, 4);
				cp += 4;
				if (address == 0)
					printf("\t0.0.0.0");
				else {
					struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

					printf("\t%s", pr_addr(&sin, sizeof sin));
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			break;
		case IPOPT_TS:
		{
			int stdtime = 0, nonstdtime = 0;
			__u8 flags;
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				break;
			flags = *++cp;
			printf("\nTS: ");
			cp++;
			for (;;) {
				long l;

				if ((flags&0xF) != IPOPT_TS_TSONLY) {
					__u32 address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = { address } };

						printf("\t%s", pr_addr(&sin, sizeof sin));
					}
					i -= 4;
					if (i <= 0)
						break;
				}
				l = *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;
				l = (l<<8) + *cp++;

				if  (l & 0x80000000) {
					if (nonstdtime==0)
						printf("\t%ld absolute not-standard", l&0x7fffffff);
					else
						printf("\t%ld not-standard", (l&0x7fffffff) - nonstdtime);
					nonstdtime = l&0x7fffffff;
				} else {
					if (stdtime==0)
						printf("\t%ld absolute", l);
					else
						printf("\t%ld", l - stdtime);
					stdtime = l;
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			if (flags>>4)
				printf("Unrecorded hops: %d\n", flags>>4);
			break;
		}
		default:
			printf("\nunknown option %x", *cp);
			break;
		}
		totlen -= optlen;
		optptr += optlen;
	}
}


/*
 * pr_iph --
 *	Print an IP header with options.
 */
void pr_iph(struct iphdr *ip)
{
	int hlen;
	unsigned char *cp;

	hlen = ip->ihl << 2;
	cp = (unsigned char *)ip + 20;		/* point to options */

	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n");
	printf(" %1x  %1x  %02x %04x %04x",
	       ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf("   %1x %04x", ((ip->frag_off) & 0xe000) >> 13,
	       (ip->frag_off) & 0x1fff);
	printf("  %02x  %02x %04x", ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	printf("\n");
	pr_options(cp, hlen);
}

/*
 * pr_addr --
 *
 * Return an ascii host address optionally with a hostname.
 */
char *
pr_addr(void *sa, socklen_t salen)
{
	static char buffer[4096] = "";
	static struct sockaddr_storage last_sa = { 0 };
	static socklen_t last_salen = 0;
	char name[NI_MAXHOST] = "";
	char address[NI_MAXHOST] = "";

	if (salen == last_salen && !memcmp(sa, &last_sa, salen))
		return buffer;

	memcpy(&last_sa, sa, (last_salen = salen));

	in_pr_addr = !setjmp(pr_addr_jmp);

	getnameinfo(sa, salen, address, sizeof address, NULL, 0, getnameinfo_flags | NI_NUMERICHOST);
	if (!exiting && !(options & F_NUMERIC))
		getnameinfo(sa, salen, name, sizeof name, NULL, 0, getnameinfo_flags);

	if (*name)
		snprintf(buffer, sizeof buffer, "%s (%s)", name, address);
	else
		snprintf(buffer, sizeof buffer, "%s", address);

	in_pr_addr = 0;

	return(buffer);
}


/* Set Type of Service (TOS) and other Quality of Service relating bits */
int parsetos(char *str)
{
	const char *cp;
	int tos;
	char *ep;

	/* handle both hex and decimal values */
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		tos = (int)strtol(cp, &ep, 16);
	} else
		tos = (int)strtol(str, &ep, 10);

	/* doesn't look like decimal or hex, eh? */
	if (*ep != '\0') {
		fprintf(stderr, "ping: \"%s\" bad value for TOS\n", str);
		exit(2);
	}

	if (tos > TOS_MAX) {
		fprintf(stderr, "ping: the decimal value of TOS bits must be 0-254 (or zero)\n");
		exit(2);
	}
	return(tos);
}

void ping4_install_filter(socket_st *sock)
{
	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LDX|BPF_B|BPF_MSH, 0), /* Skip IP header. F..g BSD... Look into ping6. */
		BPF_STMT(BPF_LD|BPF_H|BPF_IND, 4), /* Load icmp echo ident */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0xAAAA, 0, 1), /* Ours? */
		BPF_STMT(BPF_RET|BPF_K, ~0U), /* Yes, it passes. */
		BPF_STMT(BPF_LD|BPF_B|BPF_IND, 0), /* Load icmp type */
		BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET|BPF_K, 0xFFFFFFF), /* No. It passes. */
		BPF_STMT(BPF_RET|BPF_K, 0) /* Echo with wrong ident. Reject. */
	};
	static struct sock_fprog filter = {
		sizeof insns / sizeof(insns[0]),
		insns
	};

	if (once)
		return;
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, htons(ident), 0, 1);

	if (setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
		perror("WARNING: failed to install socket filter\n");
}

#define USAGE_NEWLINE	"\n           "

void usage(void)
{
	fprintf(stderr,
		"Usage: ping"
		" [-"
			"aAbBdDfhLnOqrRUvV64"
		"]"
		" [-c count]"
		" [-i interval]"
		" [-I interface]"
		USAGE_NEWLINE
		" [-m mark]"
		" [-M pmtudisc_option]"
		" [-l preload]"
		" [-p pattern]"
		" [-Q tos]"
		USAGE_NEWLINE
		" [-s packetsize]"
		" [-S sndbuf]"
		" [-t ttl]"
		" [-T timestamp_option]"
		USAGE_NEWLINE
		" [-w deadline]"
		" [-W timeout]"
		" [hop1 ...] destination"
		"\n"
	);
	ping6_usage(1);
	exit(2);
}
