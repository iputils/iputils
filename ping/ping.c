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
 *	If kernel does not support ICMP datagram sockets,
 *	this program has to run SUID to ROOT or with
 *	net_cap_raw enabled.
 */

#define _GNU_SOURCE

#include "ping.h"

#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ifaddrs.h>
#include <math.h>
#include <locale.h>
#include <sys/param.h>
#include <stdbool.h>

/* FIXME: global_rts will be removed in future */
struct ping_rts *global_rts;

char *_pr_addr(struct ping_rts *rts, void *sa, socklen_t salen, int resolve_name);

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	uint32_t	data;
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

/* max. IPv4 packet size - IPv4 header size - ICMP header size */
#define ICMP_MAX_DATALEN (MAXPACKET - 20 - 8)

/* max. IPv6 payload size - ICMPv6 Echo Reply Header */
#define ICMPV6_MAX_DATALEN (MAXPACKET - sizeof (struct icmp6_hdr))

#define CASE_TYPE(x) case x: return #x;

static char *str_family(int family)
{
	switch (family) {
		CASE_TYPE(AF_UNSPEC)
		CASE_TYPE(AF_INET)
		CASE_TYPE(AF_INET6)
	default:
		error(2, 0, _("unknown protocol family: %d"), family);
	}

	return "";
}

static char *str_socktype(int socktype)
{
	if (!socktype)
		return "0";

	switch (socktype) {
		CASE_TYPE(SOCK_DGRAM)
		CASE_TYPE(SOCK_RAW)
	default:
		error(2, 0, _("unknown sock type: %d"), socktype);
	}

	return "";
}

static int get_ipv4_optlen(struct ping_rts *rts)
{
	if (rts->opt_rroute || rts->opt_timestamp || rts->opt_sourceroute)
		return 40;

	return 0;
}

static void create_socket(struct ping_rts *rts, socket_st *sock, int family,
			  int socktype, int protocol, int requisite)
{
	int do_fallback = 0;

	errno = 0;

	assert(sock->fd == -1);
	assert(socktype == SOCK_DGRAM || socktype == SOCK_RAW);

	/* Attempt to create a ping socket if requested. Attempt to create a raw
	 * socket otherwise or as a fallback. Well known errno values follow.
	 *
	 * 1) EACCES
	 *
	 * Kernel returns EACCES for all ping socket creation attempts when the
	 * user isn't allowed to use ping socket. A range of group ids is
	 * configured using the `net.ipv4.ping_group_range` sysctl. Fallback
	 * to raw socket is necessary.
	 *
	 * Kernel returns EACCES for all raw socket creation attempts when the
	 * process doesn't have the `CAP_NET_RAW` capability.
	 *
	 * 2) EAFNOSUPPORT
	 *
	 * Kernel returns EAFNOSUPPORT for IPv6 ping or raw socket creation
	 * attempts when run with IPv6 support disabled (e.g. via `ipv6.disable=1`
	 * kernel command-line option.
	 *
	 * https://github.com/iputils/iputils/issues/32
	 *
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EAFNOSUPPORT for all IPv4 ping socket creation attempts due to lack
	 * of support in the kernel. Fallback to raw socket is necessary.
	 *
	 * https://github.com/iputils/iputils/issues/54
	 *
	 * 3) EPROTONOSUPPORT
	 *
	 * OpenVZ 2.6.32-042stab113.11 and possibly other older kernels return
	 * EPROTONOSUPPORT for all IPv6 ping socket creation attempts due to lack
	 * of support in the kernel [1]. Debian 9.5 based container with kernel 4.10
	 * returns EPROTONOSUPPORT also for IPv4 [2]. Fallback to raw socket is
	 * necessary.
	 *
	 * [1] https://github.com/iputils/iputils/issues/54
	 * [2] https://github.com/iputils/iputils/issues/129
	 */
	if (socktype == SOCK_DGRAM)
		sock->fd = socket(family, socktype, protocol);

	/* Kernel doesn't support ping sockets. */
	if (sock->fd == -1 && errno == EAFNOSUPPORT && family == AF_INET)
		do_fallback = 1;
	if (sock->fd == -1 && errno == EPROTONOSUPPORT)
		do_fallback = 1;

	/* User is not allowed to use ping sockets. */
	if (sock->fd == -1 && errno == EACCES)
		do_fallback = 1;

	if (socktype == SOCK_RAW || do_fallback) {
		socktype = SOCK_RAW;
		sock->fd = socket(family, SOCK_RAW, protocol);
	}

	sock->socktype = socktype;

	/* valid socket */
	if (sock->fd != -1)
		return;

	/* failed to create socket */

	if (requisite || rts->opt_verbose) {
		error(0, 0, "socktype: %s", str_socktype(socktype));
		error(0, errno, "socket");
	}

	if (requisite) {
		if (socktype == SOCK_RAW && geteuid() != 0)
			error(0, 0, _("=> missing cap_net_raw+p capability or setuid?"));

		exit(2);
	}
}

static void set_socket_option(socket_st *sock, int level, int optname,
			      const void *optval, socklen_t olen)
{
	if (sock->fd == -1)
		return;

	if (setsockopt(sock->fd, level, optname, optval, olen) == -1)
		error(2, errno, "setsockopt");
}

/* Much like strtod(3), but will fails if str is not valid number. */
static double ping_strtod(const char *str, const char *err_msg)
{
	double num;
	char *end = NULL;
	int strtod_errno = 0;

	if (str == NULL || *str == '\0')
		goto err;
	errno = 0;

	/*
	 * Here we always want to use locale regardless USE_IDN or ENABLE_NLS,
	 * because it handles decimal point of -i/-W input options.
	 */
	setlocale(LC_ALL, "C");
	num = strtod(str, &end);
	strtod_errno = errno;
	setlocale(LC_ALL, "");
	/* Ignore setlocale() errno (e.g. invalid locale in env). */
	errno = strtod_errno;

	if (errno || str == end || (end && *end)) {
		error(0, 0, _("option argument contains garbage: %s"), end);
		error(0, 0, _("this will become fatal error in the future"));
	}
	switch (fpclassify(num)) {
	case FP_NORMAL:
	case FP_ZERO:
		break;
	default:
		errno = ERANGE;
		goto err;
	}
	return num;
 err:
	error(2, errno, "%s: %s", err_msg, str);
	abort();	/* cannot be reached, above error() will exit */

	return 0.0;
}

static int parseflow(char *str)
{
	const char *cp;
	unsigned long val;
	char *ep;

	/* handle both hex and decimal values */
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		val = (int)strtoul(cp, &ep, 16);
	} else {
		val = (int)strtoul(str, &ep, 10);
	}

	/* doesn't look like decimal or hex, eh? */
	if (*ep != '\0')
		error(2, 0, _("bad value for flowinfo: %s"), str);

	if (val & ~IPV6_FLOWINFO_FLOWLABEL)
		error(2, 0, _("flow value is greater than 20 bits: %s"), str);

	return (val);
}

/* Set Type of Service (TOS) and other Quality of Service relating bits */
static int parsetos(char *str)
{
	const char *cp;
	int tos;
	char *ep;

	/* handle both hex and decimal values */
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
		cp = str + 2;
		tos = (int)strtol(cp, &ep, 16);
	} else {
		tos = (int)strtol(str, &ep, 10);
	}

	/* doesn't look like decimal or hex, eh? */
	if (*ep != '\0')
		error(2, 0, _("bad TOS value: %s"), str);

	if (tos > TOS_MAX)
		error(2, 0, _("the decimal value of TOS bits must be in range 0-255: %d"), tos);

	return (tos);
}

int
main(int argc, char **argv)
{
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_protocol = IPPROTO_UDP,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = getaddrinfo_flags
	};
	struct addrinfo *result, *ai;
	int ret_val;
	int ch;
	socket_st sock4 = { .fd = -1 };
	socket_st sock6 = { .fd = -1 };
	char *target;
	static struct ping_rts rts = {
		.interval = 1000,
		.preload = 1,
		.lingertime = MAXWAIT * 1000,
		.confirm_flag = MSG_CONFIRM,
		.tmin = LONG_MAX,
		.pipesize = -1,
		.datalen = DEFDATALEN,
		.ident = -1,
		.screen_width = INT_MAX,
#ifdef HAVE_LIBCAP
		.cap_raw = CAP_NET_RAW,
		.cap_admin = CAP_NET_ADMIN,
#endif
		.pmtudisc = -1,
		.source.sin_family = AF_INET,
		.source6.sin6_family = AF_INET6,
		.ni.query = -1,
		.ni.subject_type = -1,
	};
	unsigned char buf[sizeof(struct in6_addr)];

	bool opt_version = 0;

	/* FIXME: global_rts will be removed in future */
	global_rts = &rts;

	atexit(close_stdout);
	limit_capabilities(&rts);

#if defined(USE_IDN) || defined(ENABLE_NLS)
	setlocale(LC_ALL, "");
#if defined(USE_IDN)
	if (!strcmp(setlocale(LC_ALL, NULL), "C"))
		hints.ai_flags &= ~ AI_CANONIDN;
#endif
#ifdef ENABLE_NLS
	bindtextdomain (PACKAGE_NAME, LOCALEDIR);
	textdomain (PACKAGE_NAME);
#endif
#endif

	/* Support being called using `ping4` or `ping6` symlinks */
	if (argv[0][strlen(argv[0]) - 1] == '4')
		hints.ai_family = AF_INET;
	else if (argv[0][strlen(argv[0]) - 1] == '6')
		hints.ai_family = AF_INET6;

	/*
	 * Optionally disable reverse DNS resolution (PTR lookup) by default.
	 * -n/-H override the variable. Warn below if disabled due this.
	 */
	char *env = getenv("IPUTILS_PING_PTR_LOOKUP");
	int force_numeric = 0;
	if (env && !strcmp(env, "0")) {
		rts.opt_numeric = 1;
		force_numeric = 1;
	}

	/* Parse command line options */
	while ((ch = getopt(argc, argv, "h?" "4bRT:" "6F:N:" "3aABc:CdDe:fHi:I:jl:Lm:M:nOp:qQ:rs:S:t:UvVw:W:")) != EOF) {
		switch(ch) {
		/* IPv4 specific options */
		case '4':
			if (hints.ai_family == AF_INET6)
				error(2, 0, _("only one -4 or -6 option may be specified"));
			hints.ai_family = AF_INET;
			break;
		case '3':
			rts.opt_rtt_precision = 1;
			break;
		case 'b':
			rts.broadcast_pings = 1;
			break;
		case 'e':
			rts.ident = htons(strtoul_or_err(optarg, _("invalid argument"),
							 0, IDENTIFIER_MAX));
			break;
		case 'j':
			rts.opt_json = 1;
			break;
		case 'R':
			if (rts.opt_timestamp)
				error(2, 0, _("only one of -T or -R may be used"));
			rts.opt_rroute = 1;
			break;
		case 'T':
			if (rts.opt_rroute)
				error(2, 0, _("only one of -T or -R may be used"));
			rts.opt_timestamp = 1;
			if (strcmp(optarg, "tsonly") == 0)
				rts.ts_type = IPOPT_TS_TSONLY;
			else if (strcmp(optarg, "tsandaddr") == 0)
				rts.ts_type = IPOPT_TS_TSANDADDR;
			else if (strcmp(optarg, "tsprespec") == 0)
				rts.ts_type = IPOPT_TS_PRESPEC;
			else
				error(2, 0, _("invalid timestamp type: %s"), optarg);
			break;
		/* IPv6 specific options */
		case '6':
			if (hints.ai_family == AF_INET)
				error(2, 0, _("only one -4 or -6 option may be specified"));
			hints.ai_family = AF_INET6;
			break;
		case 'F':
			rts.flowlabel = parseflow(optarg);
			rts.opt_flowinfo = 1;
			break;
		case 'N':
			if (niquery_option_handler(&rts.ni, optarg) < 0)
				usage();
			hints.ai_socktype = SOCK_RAW;
			break;
		/* Common options */
		case 'a':
			rts.opt_audible = 1;
			break;
		case 'A':
			rts.opt_adaptive = 1;
			break;
		case 'B':
			rts.opt_strictsource = 1;
			break;
		case 'c':
			rts.npackets = strtol_or_err(optarg, _("invalid argument"), 1, LONG_MAX);
			break;
		case 'C':
			rts.opt_connect_sk = 1;
			break;
		case 'd':
			rts.opt_so_debug = 1;
			break;
		case 'D':
			rts.opt_ptimeofday = 1;
			break;
		case 'H':
			rts.opt_force_lookup = 1;
			break;
		case 'i':
		{
			double optval;

			optval = ping_strtod(optarg, _("bad timing interval"));
			if (isless(optval, 0) || isgreater(optval, (double)INT_MAX / 1000))
				error(2, 0, _("bad timing interval: %s"), optarg);
			rts.interval = (int)(optval * 1000);
			rts.opt_interval = 1;
		}
			break;
		case 'I':
			/* IPv6 */
			if (strchr(optarg, ':')) {
				char *p, *addr = strdup(optarg);

				if (!addr)
					error(2, errno, _("cannot copy: %s"), optarg);

				p = strchr(addr, SCOPE_DELIMITER);
				if (p) {
					*p = '\0';
					rts.device = optarg + (p - addr) + 1;
				}

				if (inet_pton(AF_INET6, addr, (char *)&rts.source6.sin6_addr) <= 0)
					error(2, 0, _("invalid source address: %s"), optarg);

				rts.opt_strictsource = 1;

				free(addr);
			} else if (inet_pton(AF_INET, optarg, &rts.source.sin_addr) > 0) {
				rts.opt_strictsource = 1;
			} else {
				rts.device = optarg;
			}
			break;
		case 'l':
			rts.preload = strtol_or_err(optarg, _("invalid argument"), 1, MAX_DUP_CHK);
			if (rts.uid && rts.preload > 3)
				error(2, 0, _("cannot set preload to value greater than 3: %d"), rts.preload);
			break;
		case 'L':
			rts.opt_noloop = 1;
			break;
		case 'm':
			rts.mark = strtoul_or_err(optarg, _("invalid argument"), 0, UINT_MAX);
			rts.opt_mark = 1;
			break;
		case 'M':
			if (strcmp(optarg, "do") == 0)
				rts.pmtudisc = IP_PMTUDISC_DO;
			else if (strcmp(optarg, "dont") == 0)
				rts.pmtudisc = IP_PMTUDISC_DONT;
			else if (strcmp(optarg, "want") == 0)
				rts.pmtudisc = IP_PMTUDISC_WANT;
			else if (strcmp(optarg, "probe") == 0)
				rts.pmtudisc = IP_PMTUDISC_PROBE;
			else
				error(2, 0, _("invalid -M argument: %s"), optarg);
			break;
		case 'n':
			rts.opt_numeric = 1;
			rts.opt_force_lookup = 0;
			break;
		case 'O':
			rts.opt_outstanding = 1;
			break;
		case 'f':
			rts.opt_flood = 1;
			/* avoid `getaddrinfo()` during flood */
			rts.opt_numeric = 1;
			setbuf(stdout, (char *)NULL);
			break;
		case 'p':
			rts.opt_pingfilled = 1;
			fill(&rts, optarg, rts.outpack, sizeof(rts.outpack));
			break;
		case 'q':
			rts.opt_quiet = 1;
			break;
		case 'Q':
			rts.settos = parsetos(optarg); /* IPv4 */
			rts.tclass = rts.settos; /* IPv6 */
			break;
		case 'r':
			rts.opt_so_dontroute = 1;
			break;
		case 's':
			/* real validation is done later */
			rts.datalen = strtol_or_err(optarg, _("invalid argument"), 0, INT_MAX);
			break;
		case 'S':
			rts.sndbuf = strtol_or_err(optarg, _("invalid argument"), 1, INT_MAX);
			break;
		case 't':
			rts.ttl = strtol_or_err(optarg, _("invalid argument"), 0, 255);
			rts.opt_ttl = 1;
			break;
		case 'U':
			rts.opt_latency = 1;
			break;
		case 'v':
			rts.opt_verbose = 1;
			break;
		case 'V':
			opt_version = 1;
			break;
		case 'w':
			rts.deadline = strtol_or_err(optarg, _("invalid argument"), 0, INT_MAX);
			break;
		case 'W':
		{
			double optval;

			optval = ping_strtod(optarg, _("bad linger time"));
			if (isless(optval, 0) || isgreater(optval, (double)INT_MAX / 1000))
				error(2, 0, _("bad linger time: %s"), optarg);
			/* lingertime will be converted to usec later */
			rts.lingertime = (int)(optval * 1000);
		}
			break;
		default:
			usage();
			break;
		}
	}

	if (opt_version) {
		ping_print_version(&rts);
		exit(0);
	}

	if (rts.opt_numeric && force_numeric && !rts.opt_quiet)
		error(0, 0, _("WARNING: reverse DNS resolution (PTR lookup) disabled, enforce with -H"));

	argc -= optind;
	argv += optind;

	if (!argc)
		error(2, EDESTADDRREQ, "usage error");

	target = argv[argc - 1];

	/* Create sockets */
	enable_capability_raw();

	/*
	 * Current Linux kernel 6.0 doesn't support on SOCK_DGRAM setting
	 * ident == 0
	 */
	if (!rts.ident) {
		if (rts.opt_verbose)
			error(0, 0, _("WARNING: ident 0 => forcing raw socket"));

		hints.ai_socktype = SOCK_RAW;
	}

	if (hints.ai_family != AF_INET6) {
		create_socket(&rts, &sock4, AF_INET, hints.ai_socktype, IPPROTO_ICMP,
			      hints.ai_family == AF_INET);
	}

	if (hints.ai_family != AF_INET) {
		create_socket(&rts, &sock6, AF_INET6, hints.ai_socktype, IPPROTO_ICMPV6, sock4.fd == -1);

		/* This may not be needed if both protocol versions always had the same value, but
		 * since I don't know that, it's better to be safe than sorry. */
		rts.pmtudisc = rts.pmtudisc == IP_PMTUDISC_DO	? IPV6_PMTUDISC_DO   :
			       rts.pmtudisc == IP_PMTUDISC_DONT ? IPV6_PMTUDISC_DONT :
			       rts.pmtudisc == IP_PMTUDISC_WANT ? IPV6_PMTUDISC_WANT :
			       rts.pmtudisc == IP_PMTUDISC_PROBE? IPV6_PMTUDISC_PROBE: rts.pmtudisc;
	}

	disable_capability_raw();

	/* Limit address family on single-protocol systems */
	if (hints.ai_family == AF_UNSPEC) {
		if (sock4.fd == -1)
			hints.ai_family = AF_INET6;
		else if (sock6.fd == -1)
			hints.ai_family = AF_INET;
	}

	int max_s = MAX(ICMP_MAX_DATALEN, ICMPV6_MAX_DATALEN);

	/* Detect based on -4 / -6 */
	if (hints.ai_family == AF_INET)
		max_s = ICMP_MAX_DATALEN - get_ipv4_optlen(&rts);
	else if (hints.ai_family == AF_INET6)
		max_s = ICMPV6_MAX_DATALEN;

	/* Force limit on IPv4/IPv6 adresses */
	if (inet_pton(AF_INET, target, buf))
		max_s = ICMP_MAX_DATALEN - get_ipv4_optlen(&rts);
	else if (inet_pton(AF_INET6, target, buf))
		max_s = ICMPV6_MAX_DATALEN;

	if (rts.datalen > max_s)
		error(EXIT_FAILURE, 0, _("invalid -s value: '%d': out of range: 0 <= value <= %d"),
		      rts.datalen, max_s);

	if (rts.opt_verbose)
		error(0, 0, "sock4.fd: %d (socktype: %s), sock6.fd: %d (socktype: %s),"
			   " hints.ai_family: %s",
			   sock4.fd, str_socktype(sock4.socktype),
			   sock6.fd, str_socktype(sock6.socktype),
			   str_family(hints.ai_family));

	/* Set socket options */
	if (rts.settos)
		set_socket_option(&sock4, IPPROTO_IP, IP_TOS, &rts.settos, sizeof(rts.settos));
	if (rts.tclass)
		set_socket_option(&sock6, IPPROTO_IPV6, IPV6_TCLASS, &rts.tclass, sizeof(rts.tclass));

	/* getaddrinfo fails to indicate a scopeid when not used in dual-stack mode.
	 * Work around by always using dual-stack name resolution.
	 *
	 * https://github.com/iputils/iputils/issues/252
	 */
	int target_ai_family = hints.ai_family;
	hints.ai_family = AF_UNSPEC;

	if (!strchr(target, '%') && sock6.socktype == SOCK_DGRAM &&
		inet_pton(AF_INET6, target, buf) > 0 &&
		(IN6_IS_ADDR_LINKLOCAL(buf) || IN6_IS_ADDR_MC_LINKLOCAL(buf))) {
			error(0, 0, _(
				"Warning: IPv6 link-local address on ICMP datagram socket may require ifname or scope-id"
				" => use: address%%<ifname|scope-id>"));
	}

	ret_val = getaddrinfo(target, NULL, &hints, &result);
	if (ret_val)
		error(2, 0, "%s: %s", target, gai_strerror(ret_val));

	for (ai = result; ai; ai = ai->ai_next) {
		if (rts.opt_verbose)
			error(0, 0, "ai->ai_family: %s, ai->ai_canonname: '%s'",
				   str_family(ai->ai_family),
				   ai->ai_canonname ? ai->ai_canonname : "");

		if (target_ai_family != AF_UNSPEC &&
			target_ai_family != ai->ai_family) {
			if (!ai->ai_next) {
				/* An address was found, but not of the family we really want.
				 * Throw the appropriate gai error.
				 */
				error(2, 0, "%s: %s", target, gai_strerror(EAI_ADDRFAMILY));
			}
			continue;
		}
		switch (ai->ai_family) {
		case AF_INET:
			ret_val = ping4_run(&rts, argc, argv, ai, &sock4);
			break;
		case AF_INET6:
			ret_val = ping6_run(&rts, argc, argv, ai, &sock6);
			break;
		default:
			error(2, 0, _("unknown protocol family: %d"), ai->ai_family);
		}

		if (ret_val >= 0)
			break;
		/* ret_val < 0 means to go on to next addrinfo result, there
		 * better be one. */
		assert(ai->ai_next);
	}

	freeaddrinfo(result);

	return ret_val;
}

static int iface_name2index(struct ping_rts *rts, int fd)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, rts->device, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
		error(2, 0, _("unknown iface: %s"), rts->device);

	return ifr.ifr_ifindex;
}

static void bind_to_device(struct ping_rts *rts, int fd, in_addr_t addr)
{
	int rc;
	int errno_save;

	enable_capability_raw();
	rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, rts->device,
			strlen(rts->device) + 1);
	errno_save = errno;
	disable_capability_raw();

	if (rc != -1)
		return;

	if (IN_MULTICAST(ntohl(addr))) {
		struct ip_mreqn imr;

		memset(&imr, 0, sizeof(imr));
		imr.imr_ifindex = iface_name2index(rts, fd);

		if (setsockopt(fd, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr)) == -1)
			error(2, errno, "IP_MULTICAST_IF");
	} else {
		error(2, errno_save, "SO_BINDTODEVICE %s", rts->device);
	}
}

/* return >= 0: exit with this code, < 0: go on to next addrinfo result */
int ping4_run(struct ping_rts *rts, int argc, char **argv, struct addrinfo *ai,
	      socket_st *sock)
{
	static const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_protocol = IPPROTO_UDP,
		.ai_flags = getaddrinfo_flags
	};
	int hold, packlen;
	unsigned char *packet;
	char *target;
	char hnamebuf[NI_MAXHOST];
	unsigned char rspace[3 + 4 * NROUTES + 1];	/* record route space */
	uint32_t *tmp_rspace;
	struct sockaddr_in dst;
	int ret;

	if (argc > 1) {
		if (rts->opt_rroute)
			usage();
		else if (rts->opt_timestamp) {
			if (rts->ts_type != IPOPT_TS_PRESPEC)
				usage();
			if (argc > 5)
				usage();
		} else {
			if (argc > 10)
				usage();
			rts->opt_sourceroute = 1;
		}
	}
	while (argc > 0) {
		target = *argv;

		memset((char *)&rts->whereto, 0, sizeof(rts->whereto));
		rts->whereto.sin_family = AF_INET;
		if (inet_aton(target, &rts->whereto.sin_addr) == 1) {
			rts->hostname = target;
			if (argc == 1)
				rts->opt_numeric = 1;
		} else {
			struct addrinfo *result = ai;
			int ret_val;

			if (argc > 1) {
				ret_val = getaddrinfo(target, NULL, &hints, &result);
				if (ret_val)
					error(2, 0, "%s: %s", target, gai_strerror(ret_val));
			}

			memcpy(&rts->whereto, result->ai_addr, sizeof rts->whereto);
			memset(hnamebuf, 0, sizeof hnamebuf);

			/*
			 * On certain network setup getaddrinfo() can return empty
			 * ai_canonname. Instead of printing nothing in "PING"
			 * line use the target.
			 */
			if (result->ai_canonname)
				strncpy(hnamebuf, result->ai_canonname, sizeof hnamebuf - 1);
			else
				strncpy(hnamebuf, target, sizeof hnamebuf - 1);

			rts->hostname = hnamebuf;

			if (argc > 1)
				freeaddrinfo(result);
		}
		if (argc > 1)
			rts->route[rts->nroute++] = rts->whereto.sin_addr.s_addr;
		argc--;
		argv++;
	}

	if (rts->source.sin_addr.s_addr == 0) {
		socklen_t alen;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
		dst = rts->whereto;

		if (probe_fd < 0)
			error(2, errno, "socket");

		if (rts->device) {
			bind_to_device(rts, probe_fd, dst.sin_addr.s_addr);
			bind_to_device(rts, sock->fd, dst.sin_addr.s_addr);
		}

		if (rts->settos &&
		    setsockopt(probe_fd, IPPROTO_IP, IP_TOS, (char *)&rts->settos, sizeof(int)) < 0)
			error(0, errno, _("warning: QOS sockopts"));

		sock_setmark(rts, probe_fd);

		dst.sin_port = htons(1025);
		if (rts->nroute)
			dst.sin_addr.s_addr = rts->route[0];
		if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) == -1) {
			if (errno == EACCES) {
				if (rts->broadcast_pings == 0)
					error(2, 0,
						_("Do you want to ping broadcast? Then -b. If not, check your local firewall rules"));
				fprintf(stderr, _("WARNING: pinging broadcast address\n"));
				if (setsockopt(probe_fd, SOL_SOCKET, SO_BROADCAST,
					       &rts->broadcast_pings, sizeof(rts->broadcast_pings)) < 0)
					error(2, errno, _("cannot set broadcasting"));
				if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) == -1)
					error(2, errno, "connect");
			} else if ((errno == EHOSTUNREACH || errno == ENETUNREACH) && ai->ai_next) {
				close(probe_fd);
				return -1;
			} else {
				error(2, errno, "connect");
			}
		}
		alen = sizeof(rts->source);
		if (getsockname(probe_fd, (struct sockaddr *)&rts->source, &alen) == -1)
			error(2, errno, "getsockname");
		rts->source.sin_port = 0;

		if (rts->device) {
			struct ifaddrs *ifa0, *ifa;
			int ret;

			ret = getifaddrs(&ifa0);
			if (ret)
				error(2, errno, _("gatifaddrs failed"));
			for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
				if (!ifa->ifa_name || !ifa->ifa_addr ||
				    ifa->ifa_addr->sa_family != AF_INET)
					continue;
				if (!strcmp(ifa->ifa_name, rts->device) &&
				    !memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					    &rts->source.sin_addr, sizeof(rts->source.sin_addr)))
					break;
			}
			freeifaddrs(ifa0);
			if (!ifa)
				error(0, 0, _("Warning: source address might be selected on device other than: %s"), rts->device);
		}
		close(probe_fd);

	} else if (rts->device) {
		bind_to_device(rts, sock->fd, rts->whereto.sin_addr.s_addr);
	}

	if (rts->whereto.sin_addr.s_addr == 0)
		rts->whereto.sin_addr.s_addr = rts->source.sin_addr.s_addr;

	if (rts->broadcast_pings || IN_MULTICAST(ntohl(rts->whereto.sin_addr.s_addr))) {
		rts->multicast = 1;

		if (rts->uid) {
			if (rts->interval < MIN_MULTICAST_USER_INTERVAL_MS)
				error(2, 0, _("minimal interval for broadcast ping for user must be >= %d ms, use -i %s (or higher)"),
					  MIN_MULTICAST_USER_INTERVAL_MS,
					  str_interval(MIN_MULTICAST_USER_INTERVAL_MS));

			if (rts->pmtudisc >= 0 && rts->pmtudisc != IP_PMTUDISC_DO)
				error(2, 0, _("broadcast ping does not fragment"));
		}

		if (rts->pmtudisc < 0)
			rts->pmtudisc = IP_PMTUDISC_DO;
	}

	if (rts->pmtudisc >= 0) {
		if (setsockopt(sock->fd, SOL_IP, IP_MTU_DISCOVER, &rts->pmtudisc, sizeof rts->pmtudisc) == -1)
			error(2, errno, "IP_MTU_DISCOVER");
	}

	int set_ident = rts->ident > 0 && sock->socktype == SOCK_DGRAM;
	if (set_ident)
		rts->source.sin_port = rts->ident;

	if (rts->opt_strictsource || set_ident) {
		if (bind(sock->fd, (struct sockaddr *)&rts->source, sizeof rts->source) == -1)
			error(2, errno, "bind");
	}

	if (sock->socktype == SOCK_RAW) {
		struct icmp_filter filt;
		filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
			      (1 << ICMP_DEST_UNREACH)	|
			      (1 << ICMP_TIME_EXCEEDED) |
			      (1 << ICMP_PARAMETERPROB) |
			      (1 << ICMP_REDIRECT)	|
			      (1 << ICMP_ECHOREPLY));
		if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == -1)
			error(0, errno, _("WARNING: setsockopt(ICMP_FILTER)"));
	}

	hold = 1;
	if (setsockopt(sock->fd, SOL_IP, IP_RECVERR, &hold, sizeof hold))
		error(0, 0, _("WARNING: your kernel is veeery old. No problems."));

	if (sock->socktype == SOCK_DGRAM) {
		if (setsockopt(sock->fd, SOL_IP, IP_RECVTTL, &hold, sizeof hold))
			error(0, errno, _("WARNING: setsockopt(IP_RECVTTL)"));
		if (setsockopt(sock->fd, SOL_IP, IP_RETOPTS, &hold, sizeof hold))
			error(0, errno, _("WARNING: setsockopt(IP_RETOPTS)"));
	}

	/* record route option */
	if (rts->opt_rroute) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOP;
		rspace[1 + IPOPT_OPTVAL] = IPOPT_RR;
		rspace[1 + IPOPT_OLEN] = sizeof(rspace) - 1;
		rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, sizeof rspace) < 0)
			error(2, errno, "record route");
	}
	if (rts->opt_timestamp) {
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = (rts->ts_type == IPOPT_TS_TSONLY ? 40 : 36);
		rspace[2] = 5;
		rspace[3] = rts->ts_type;
		if (rts->ts_type == IPOPT_TS_PRESPEC) {
			int i;
			rspace[1] = 4 + rts->nroute * 8;
			for (i = 0; i < rts->nroute; i++) {
				tmp_rspace = (uint32_t *)&rspace[4 + i * 8];
				*tmp_rspace = rts->route[i];
			}
		}
		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0) {
			rspace[3] = 2;
			if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, rspace[1]) < 0)
				error(2, errno, "ts option");
		}
	}
	if (rts->opt_sourceroute) {
		int i;
		memset(rspace, 0, sizeof(rspace));
		rspace[0] = IPOPT_NOOP;
		rspace[1 + IPOPT_OPTVAL] = rts->opt_so_dontroute ? IPOPT_SSRR : IPOPT_LSRR;
		rspace[1 + IPOPT_OLEN] = 3 + rts->nroute * 4;
		rspace[1 + IPOPT_OFFSET] = IPOPT_MINOFF;
		for (i = 0; i < rts->nroute; i++) {
			tmp_rspace = (uint32_t *)&rspace[4 + i * 4];
			*tmp_rspace = rts->route[i];
		}

		if (setsockopt(sock->fd, IPPROTO_IP, IP_OPTIONS, rspace, 4 + rts->nroute * 4) < 0)
			error(2, errno, "record route");
	}

	rts->optlen = get_ipv4_optlen(rts);

	/* Estimate memory eaten by single packet. It is rough estimate.
	 * Actually, for small datalen's it depends on kernel side a lot. */
	hold = rts->datalen + 8;
	hold += ((hold + 511) / 512) * (rts->optlen + 20 + 16 + 64 + 160);
	sock_setbufs(rts, sock, hold);

	if (rts->broadcast_pings) {
		if (setsockopt(sock->fd, SOL_SOCKET, SO_BROADCAST, &rts->broadcast_pings,
			       sizeof rts->broadcast_pings) < 0)
			error(2, errno, _("cannot set broadcasting"));
	}

	if (rts->opt_noloop) {
		int loop = 0;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop) == -1)
			error(2, errno, _("cannot disable multicast loopback"));
	}
	if (rts->opt_ttl) {
		int ittl = rts->ttl;
		if (setsockopt(sock->fd, IPPROTO_IP, IP_MULTICAST_TTL, &rts->ttl, sizeof rts->ttl) == -1)
			error(2, errno, _("cannot set multicast time-to-live"));
		if (setsockopt(sock->fd, IPPROTO_IP, IP_TTL, &ittl, sizeof ittl) == -1)
			error(2, errno, _("cannot set unicast time-to-live"));
	}

	if (rts->datalen >= (int)sizeof(struct timeval))	/* can we time transfer */
		rts->timing = 1;
	packlen = rts->datalen + MAXIPLEN + MAXICMPLEN;
	if (!(packet = (unsigned char *)malloc((unsigned int)packlen)))
		error(2, errno, _("memory allocation failed"));

	ping_print_packet(rts);

	setup(rts, sock);
	if (rts->opt_connect_sk &&
	    connect(sock->fd, (struct sockaddr *)&dst, sizeof(dst)) == -1)
		error(2, errno, "connect failed");

	drop_capabilities();

	ret = main_loop(rts, &ping4_func_set, sock, packet, packlen);
	free(packet);

	return ret;
}

static void pr_options(struct ping_rts *rts, unsigned char *cp, int hlen)
{
	int i, j;
	int olen, totlen;
	unsigned char *optptr;
	static int old_rrlen;
	static char old_rr[MAX_IPOPTLEN];

	totlen = hlen - sizeof(struct iphdr);
	optptr = cp;

	while (totlen > 0) {
		if (*optptr == IPOPT_EOL)
			break;
		if (*optptr == IPOPT_NOP) {
			totlen--;
			optptr++;
			printf(_("\nNOP"));
			continue;
		}
		cp = optptr;
		olen = optptr[1];
		if (olen < 2 || olen > totlen)
			break;

		switch (*cp) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			printf(_("\n%cSRR: "), *cp == IPOPT_SSRR ? 'S' : 'L');
			j = *++cp;
			cp++;
			if (j > IPOPT_MINOFF) {
				for (;;) {
					uint32_t address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = {
							.sin_family = AF_INET,
							.sin_addr = {
								address
							}
						};

						printf("\t%s", pr_addr(rts, &sin, sizeof sin));
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
			    && !rts->opt_flood) {
				printf(_("\t(same route)"));
				break;
			}
			old_rrlen = i;
			memcpy(old_rr, (char *)cp, i);
			printf(_("\nRR: "));
			cp++;
			for (;;) {
				uint32_t address;
				memcpy(&address, cp, 4);
				cp += 4;
				if (address == 0)
					printf("\t0.0.0.0");
				else {
					struct sockaddr_in sin = {
						.sin_family = AF_INET,
						.sin_addr = {
							address
						}
					};

					printf("\t%s", pr_addr(rts, &sin, sizeof sin));
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
			uint8_t flags;
			j = *++cp;		/* get length */
			i = *++cp;		/* and pointer */
			if (i > j)
				i = j;
			i -= 5;
			if (i <= 0)
				break;
			flags = *++cp;
			printf(_("\nTS: "));
			cp++;
			for (;;) {
				long l;

				if ((flags & 0xF) != IPOPT_TS_TSONLY) {
					uint32_t address;
					memcpy(&address, cp, 4);
					cp += 4;
					if (address == 0)
						printf("\t0.0.0.0");
					else {
						struct sockaddr_in sin = {
							.sin_family = AF_INET,
							.sin_addr = {
								address
							}
						};

						printf("\t%s", pr_addr(rts, &sin, sizeof sin));
					}
					i -= 4;
					if (i <= 0)
						break;
				}
				l = *cp++;
				l = (l << 8) + *cp++;
				l = (l << 8) + *cp++;
				l = (l << 8) + *cp++;

				if (l & 0x80000000) {
					if (nonstdtime == 0)
						printf(_("\t%ld absolute not-standard"), l & 0x7fffffff);
					else
						printf(_("\t%ld not-standard"), (l & 0x7fffffff) - nonstdtime);
					nonstdtime = l & 0x7fffffff;
				} else {
					if (stdtime == 0)
						printf(_("\t%ld absolute"), l);
					else
						printf("\t%ld", l - stdtime);
					stdtime = l;
				}
				i -= 4;
				putchar('\n');
				if (i <= 0)
					break;
			}
			if (flags >> 4)
				printf(_("Unrecorded hops: %d\n"), flags >> 4);
			break;
		}
		default:
			printf(_("\nunknown option %x"), *cp);
			break;
		}
		totlen -= olen;
		optptr += olen;
	}
}

/*
 * pr_iph --
 *	Print an IP header with options.
 */
static void pr_iph(struct ping_rts *rts, struct iphdr *ip)
{
	int hlen;
	unsigned char *cp;

	hlen = ip->ihl << 2;
	cp = (unsigned char *)ip + 20;		/* point to options */

	printf(_("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst Data\n"));
	printf(_(" %1x  %1x  %02x %04x %04x"),
	       ip->version, ip->ihl, ip->tos, ip->tot_len, ip->id);
	printf(_("   %1x %04x"), ((ip->frag_off) & 0xe000) >> 13,
	       (ip->frag_off) & 0x1fff);
	printf(_("  %02x  %02x %04x"), ip->ttl, ip->protocol, ip->check);
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf(" %s ", inet_ntoa(*(struct in_addr *)&ip->daddr));
	printf("\n");
	pr_options(rts, cp, hlen);
}

/*
 * pr_icmph --
 *	Print a descriptive string about an ICMP header.
 */
static void pr_icmph(struct ping_rts *rts, uint8_t type, uint8_t code,
		     uint32_t info, struct icmphdr *icp)
{
	switch (type) {
	case ICMP_ECHOREPLY:
		printf(_("Echo Reply\n"));
		/* XXX ID + Seq + Data */
		break;
	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_NET_UNREACH:
			printf(_("Destination Net Unreachable\n"));
			break;
		case ICMP_HOST_UNREACH:
			printf(_("Destination Host Unreachable\n"));
			break;
		case ICMP_PROT_UNREACH:
			printf(_("Destination Protocol Unreachable\n"));
			break;
		case ICMP_PORT_UNREACH:
			printf(_("Destination Port Unreachable\n"));
			break;
		case ICMP_FRAG_NEEDED:
			printf(_("Frag needed and DF set (mtu = %u)\n"), info);
			break;
		case ICMP_SR_FAILED:
			printf(_("Source Route Failed\n"));
			break;
		case ICMP_NET_UNKNOWN:
			printf(_("Destination Net Unknown\n"));
			break;
		case ICMP_HOST_UNKNOWN:
			printf(_("Destination Host Unknown\n"));
			break;
		case ICMP_HOST_ISOLATED:
			printf(_("Source Host Isolated\n"));
			break;
		case ICMP_NET_ANO:
			printf(_("Destination Net Prohibited\n"));
			break;
		case ICMP_HOST_ANO:
			printf(_("Destination Host Prohibited\n"));
			break;
		case ICMP_NET_UNR_TOS:
			printf(_("Destination Net Unreachable for Type of Service\n"));
			break;
		case ICMP_HOST_UNR_TOS:
			printf(_("Destination Host Unreachable for Type of Service\n"));
			break;
		case ICMP_PKT_FILTERED:
			printf(_("Packet filtered\n"));
			break;
		case ICMP_PREC_VIOLATION:
			printf(_("Precedence Violation\n"));
			break;
		case ICMP_PREC_CUTOFF:
			printf(_("Precedence Cutoff\n"));
			break;
		default:
			printf(_("Dest Unreachable, Bad Code: %d\n"), code);
			break;
		}
		if (icp && rts->opt_verbose)
			pr_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_SOURCE_QUENCH:
		printf(_("Source Quench\n"));
		if (icp && rts->opt_verbose)
			pr_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_REDIRECT:
		switch (code) {
		case ICMP_REDIR_NET:
			printf(_("Redirect Network"));
			break;
		case ICMP_REDIR_HOST:
			printf(_("Redirect Host"));
			break;
		case ICMP_REDIR_NETTOS:
			printf(_("Redirect Type of Service and Network"));
			break;
		case ICMP_REDIR_HOSTTOS:
			printf(_("Redirect Type of Service and Host"));
			break;
		default:
			printf(_("Redirect, Bad Code: %d"), code);
			break;
		}
		{
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_addr =  {
					icp ? icp->un.gateway : htonl(info)
				}
			};

			printf(_("(New nexthop: %s)\n"), pr_addr(rts, &sin, sizeof sin));
		}
		if (icp && rts->opt_verbose)
			pr_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_ECHO:
		printf(_("Echo Request\n"));
		/* XXX ID + Seq + Data */
		break;
	case ICMP_TIME_EXCEEDED:
		switch(code) {
		case ICMP_EXC_TTL:
			printf(_("Time to live exceeded\n"));
			break;
		case ICMP_EXC_FRAGTIME:
			printf(_("Frag reassembly time exceeded\n"));
			break;
		default:
			printf(_("Time exceeded, Bad Code: %d\n"), code);
			break;
		}
		if (icp && rts->opt_verbose)
			pr_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_PARAMETERPROB:
		printf(_("Parameter problem: pointer = %u\n"),
			icp ? (ntohl(icp->un.gateway) >> 24) : info);
		if (icp && rts->opt_verbose)
			pr_iph(rts, (struct iphdr *)(icp + 1));
		break;
	case ICMP_TIMESTAMP:
		printf(_("Timestamp\n"));
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_TIMESTAMPREPLY:
		printf(_("Timestamp Reply\n"));
		/* XXX ID + Seq + 3 timestamps */
		break;
	case ICMP_INFO_REQUEST:
		printf(_("Information Request\n"));
		/* XXX ID + Seq */
		break;
	case ICMP_INFO_REPLY:
		printf(_("Information Reply\n"));
		/* XXX ID + Seq */
		break;
#ifdef ICMP_MASKREQ
	case ICMP_MASKREQ:
		printf(_("Address Mask Request\n"));
		break;
#endif
#ifdef ICMP_MASKREPLY
	case ICMP_MASKREPLY:
		printf(_("Address Mask Reply\n"));
		break;
#endif
	default:
		printf(_("Bad ICMP type: %d\n"), type);
	}
}

int ping4_receive_error_msg(struct ping_rts *rts, socket_st *sock)
{
	ssize_t res;
	char cbuf[512];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsgh;
	struct sock_extended_err *e;
	struct icmphdr icmph;
	struct sockaddr_in target;
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
	for (cmsgh = CMSG_FIRSTHDR(&msg); cmsgh; cmsgh = CMSG_NXTHDR(&msg, cmsgh)) {
		if (cmsgh->cmsg_level == SOL_IP) {
			if (cmsgh->cmsg_type == IP_RECVERR)
				e = (struct sock_extended_err *)CMSG_DATA(cmsgh);
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
			ping_error(rts, 0, 0, _("local error: message too long, mtu=%u"), e->ee_info);
		rts->nerrors++;
	} else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
		struct sockaddr_in *sin = (struct sockaddr_in *)(e + 1);

		if (res < (ssize_t) sizeof(icmph) ||
		    target.sin_addr.s_addr != rts->whereto.sin_addr.s_addr ||
		    icmph.type != ICMP_ECHO ||
		    !is_ours(rts, sock, icmph.un.echo.id)) {
			/* Not our error, not an error at all. Clear. */
			saved_errno = 0;
			goto out;
		}

		acknowledge(rts, ntohs(icmph.un.echo.sequence));

		if (sock->socktype == SOCK_RAW) {
			struct icmp_filter filt;

			filt.data = ~((1 << ICMP_SOURCE_QUENCH) |
				      (1 << ICMP_REDIRECT) |
				      (1 << ICMP_ECHOREPLY));
			if (setsockopt(sock->fd, SOL_RAW, ICMP_FILTER, (const void *)&filt,
				       sizeof(filt)) == -1)
				ping_error(rts, 2, errno, "setsockopt(ICMP_FILTER)");
		}
		net_errors++;
		rts->nerrors++;
		if (rts->opt_quiet)
			goto out;
		if (rts->opt_flood) {
			write_stdout("\bE", 2);
		} else {
			print_timestamp(rts);
			ping_print_error_packet(rts, pr_addr(rts, sin, sizeof *sin), ntohs(icmph.un.echo.sequence));
			pr_icmph(rts, e->ee_type, e->ee_code, e->ee_info, NULL);
			fflush(stdout);
		}
	}

out:
	errno = saved_errno;
	return net_errors ? net_errors : -local_errors;
}

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

static unsigned short
in_cksum(const unsigned short *addr, int len, unsigned short csum)
{
	int nleft = len;
	const unsigned short *w = addr;
	unsigned short answer;
	int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
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
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int ping4_send_probe(struct ping_rts *rts, socket_st *sock, void *packet,
		     unsigned packet_size __attribute__((__unused__)))
{
	struct icmphdr *icp;
	int cc;
	int i;

	icp = (struct icmphdr *)packet;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = htons(rts->ntransmitted + 1);
	icp->un.echo.id = rts->ident;			/* ID */

	rcvd_clear(rts, rts->ntransmitted + 1);

	if (rts->timing) {
		if (rts->opt_latency) {
			struct timeval tmp_tv;
			gettimeofday(&tmp_tv, NULL);
			memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
		} else {
			memset(icp + 1, 0, sizeof(struct timeval));
		}
	}

	cc = rts->datalen + 8;			/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum((unsigned short *)icp, cc, 0);

	if (rts->timing && !rts->opt_latency) {
		struct timeval tmp_tv;
		gettimeofday(&tmp_tv, NULL);
		memcpy(icp + 1, &tmp_tv, sizeof(tmp_tv));
		icp->checksum = in_cksum((unsigned short *)&tmp_tv, sizeof(tmp_tv), ~icp->checksum);
	}

	i = sendto(sock->fd, icp, cc, 0, (struct sockaddr *)&rts->whereto, sizeof(rts->whereto));

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
void pr_echo_reply(struct ping_rts *rts, uint8_t *_icp, int len __attribute__((__unused__)))
{
	struct icmphdr *icp = (struct icmphdr *)_icp;

	ping_print_uint(rts, _(" icmp_seq=%u"), "seq", ntohs(icp->un.echo.sequence));
}

int ping4_parse_reply(struct ping_rts *rts, struct socket_st *sock,
		      struct msghdr *msg, int cc, void *addr,
		      struct timeval *tv)
{
	struct sockaddr_in *from = addr;
	uint8_t *buf = msg->msg_iov->iov_base;
	struct icmphdr *icp;
	struct iphdr *ip;
	int hlen;
	int csfailed;
	struct cmsghdr *cmsgh;
	int reply_ttl;
	uint8_t *opts, *tmp_ttl;
	int olen;
	int wrong_source = 0;

	/* Check the IP header */
	ip = (struct iphdr *)buf;
	if (sock->socktype == SOCK_RAW) {
		hlen = ip->ihl * 4;
		if (cc < hlen + 8 || ip->ihl < 5) {
			if (rts->opt_verbose)
				ping_error(rts, 0, 0, _("packet too short (%d bytes) from %s"), cc,
					pr_addr(rts,from, sizeof *from));
			return 1;
		}
		reply_ttl = ip->ttl;
		opts = buf + sizeof(struct iphdr);
		olen = hlen - sizeof(struct iphdr);
	} else {
		hlen = 0;
		reply_ttl = 0;
		opts = buf;
		olen = 0;
		for (cmsgh = CMSG_FIRSTHDR(msg); cmsgh; cmsgh = CMSG_NXTHDR(msg, cmsgh)) {
			if (cmsgh->cmsg_level != SOL_IP)
				continue;
			if (cmsgh->cmsg_type == IP_TTL) {
				if (cmsgh->cmsg_len < sizeof(int))
					continue;
				tmp_ttl = (uint8_t *)CMSG_DATA(cmsgh);
				reply_ttl = (int)*tmp_ttl;
			} else if (cmsgh->cmsg_type == IP_RETOPTS) {
				opts = (uint8_t *)CMSG_DATA(cmsgh);
				olen = cmsgh->cmsg_len;
			}
		}
	}

	/* Now the ICMP part */
	cc -= hlen;
	icp = (struct icmphdr *)(buf + hlen);
	csfailed = in_cksum((unsigned short *)icp, cc, 0);

	if (icp->type == ICMP_ECHOREPLY) {
		if (!is_ours(rts, sock, icp->un.echo.id))
			return 1;			/* 'Twas not our ECHO */

		if (!rts->broadcast_pings && !rts->multicast &&
		    from->sin_addr.s_addr != rts->whereto.sin_addr.s_addr)
			wrong_source = 1;
		if (gather_statistics(rts, (uint8_t *)icp, sizeof(*icp), cc,
				      ntohs(icp->un.echo.sequence),
				      reply_ttl, csfailed, tv, pr_addr(rts, from, sizeof *from),
				      pr_echo_reply, rts->multicast, wrong_source)) {
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
				struct iphdr *iph = (struct iphdr *)(&icp[1]);
				struct icmphdr *icp1 = (struct icmphdr *)
						((unsigned char *)iph + iph->ihl * 4);
				int error_pkt;
				if (cc < (int)(8 + sizeof(struct iphdr) + 8) ||
				    cc < 8 + iph->ihl * 4 + 8)
					return 1;
				if (icp1->type != ICMP_ECHO ||
				    iph->daddr != rts->whereto.sin_addr.s_addr ||
				    !is_ours(rts, sock, icp1->un.echo.id))
					return 1;
				error_pkt = (icp->type != ICMP_REDIRECT &&
					     icp->type != ICMP_SOURCE_QUENCH);
				if (error_pkt) {
					acknowledge(rts, ntohs(icp1->un.echo.sequence));
					return 0;
				}
				if (rts->opt_quiet || rts->opt_flood)
					return 1;
				print_timestamp(rts);
				printf(_("From %s: icmp_seq=%u "), pr_addr(rts, from, sizeof *from),
				       ntohs(icp1->un.echo.sequence));
				if (csfailed)
					printf(_("(BAD CHECKSUM)"));
				pr_icmph(rts, icp->type, icp->code, ntohl(icp->un.gateway), icp);
				return 1;
			}
		default:
			/* MUST NOT */
			break;
		}
		if (rts->opt_flood && !(rts->opt_verbose || rts->opt_quiet)) {
			if (!csfailed)
				write_stdout("!E", 2);
			else
				write_stdout("!EC", 3);
			return 0;
		}
		if (!rts->opt_verbose || rts->uid)
			return 0;
		if (rts->opt_ptimeofday) {
			struct timeval recv_time;
			gettimeofday(&recv_time, NULL);
			printf("%lu.%06lu ", (unsigned long)recv_time.tv_sec, (unsigned long)recv_time.tv_usec);
		}
		printf(_("From %s: "), pr_addr(rts, from, sizeof *from));
		if (csfailed) {
			printf(_("(BAD CHECKSUM)\n"));
			return 0;
		}
		pr_icmph(rts, icp->type, icp->code, ntohl(icp->un.gateway), icp);
		return 0;
	}

	if (rts->opt_audible) {
		putchar('\a');
		if (rts->opt_flood)
			fflush(stdout);
	}
	if (!rts->opt_flood) {
		pr_options(rts, opts, olen + sizeof(struct iphdr));

		ping_finish_line(rts);
	}

	return 0;
}

/*
 * pr_addr --
 *
 * Return an ascii host address with reverse name resolution.
 */
char *pr_addr(struct ping_rts *rts, void *sa, socklen_t salen)
{
	return _pr_addr(rts, sa, salen, 1);
}

/*
 * pr_raw_addr --
 *
 * Return an ascii host address.  Reverse name resolution is not performed.
 */

char *pr_raw_addr(struct ping_rts *rts, void *sa, socklen_t salen)
{
	return _pr_addr(rts, sa, salen, 0);
}

/*
 * _pr_addr --
 *
 * Return an ascii host address optionally with a hostname.
 */
char *_pr_addr(struct ping_rts *rts, void *sa, socklen_t salen, int resolve_name)
{
	static char buffer[4096] = "";
	static struct sockaddr_storage last_sa = {0};
	static socklen_t last_salen = 0;
	char name[NI_MAXHOST] = "";
	char address[NI_MAXHOST] = "";

	if (salen == last_salen && !memcmp(sa, &last_sa, salen))
		return buffer;

	memcpy(&last_sa, sa, (last_salen = salen));

	rts->in_pr_addr = !setjmp(rts->pr_addr_jmp);

	getnameinfo(sa, salen, address, sizeof address, NULL, 0, getnameinfo_flags | NI_NUMERICHOST);
	if (!rts->exiting && resolve_name && (rts->opt_force_lookup || !rts->opt_numeric))
		getnameinfo(sa, salen, name, sizeof name, NULL, 0, getnameinfo_flags);

	if (*name && strncmp(name, address, NI_MAXHOST))
		snprintf(buffer, sizeof buffer, "%s (%s)", name, address);
	else
		snprintf(buffer, sizeof buffer, "%s", address);

	rts->in_pr_addr = 0;

	return (buffer);
}


void ping4_install_filter(struct ping_rts *rts, socket_st *sock)
{
	static int once;
	static struct sock_filter insns[] = {
		BPF_STMT(BPF_LDX | BPF_B   | BPF_MSH, 0),	/* Skip IP header due BSD, see ping6. */
		BPF_STMT(BPF_LD  | BPF_H   | BPF_IND, 4),	/* Load icmp echo ident */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xAAAA, 0, 1), /* Ours? */
		BPF_STMT(BPF_RET | BPF_K, ~0U),			/* Yes, it passes. */
		BPF_STMT(BPF_LD  | BPF_B   | BPF_IND, 0),	/* Load icmp type */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ICMP_ECHOREPLY, 1, 0), /* Echo? */
		BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFF),		/* No. It passes. */
		BPF_STMT(BPF_RET | BPF_K, 0)			/* Echo with wrong ident. Reject. */
	};
	static struct sock_fprog filter = {
		sizeof insns / sizeof(insns[0]),
		insns
	};

	if (once)
		return;
	once = 1;

	/* Patch bpflet for current identifier. */
	insns[2] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(rts->ident), 0, 1);

	if (setsockopt(sock->fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)))
		ping_error(rts, 0, errno, _("WARNING: failed to install socket filter"));
}
