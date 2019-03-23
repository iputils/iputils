/* $USAGI: ninfod.c,v 1.34 2003-01-15 06:41:23 mk Exp $ */
/*
 * Copyright (C) 2002 USAGI/WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Author:
 * 	YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>
# include <stddef.h>
# include <stdarg.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif

#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif
#if HAVE_LIMITS_H
# include <limits.h>
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <sys/socket.h>

#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if HAVE_NETINET_ICMP6_H
# include <netinet/icmp6.h>
#endif
#ifndef HAVE_STRUCT_ICMP6_NODEINFO
# include "icmp6_nodeinfo.h"
#endif

#if HAVE_NETDB_H
# include <netdb.h>
#endif
#include <errno.h>

#include <signal.h>

#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

#if HAVE_PWD_H
# include <pwd.h>
#endif

#if HAVE_SYS_CAPABILITY_H
# include <sys/prctl.h>
# include <sys/capability.h>
#endif

#include "iputils_common.h"
#include "iputils_ni.h"
#include "ninfod.h"

/* Variables */
int sock;
int daemonized;

char *appname;
static int opt_d = 0;	/* debug */
static int opt_h = 0;	/* help */
static char *opt_p = NINFOD_PIDFILE;	/* pidfile */
static int got_signal = 0;	/* loop unless true */
int opt_v = 0;		/* verbose */
static uid_t opt_u;

static int ipv6_pktinfo = IPV6_PKTINFO;

/* --------- */
#if ENABLE_DEBUG
__inline__ static const char * log_level(int priority) {
	switch(priority) {
	case LOG_EMERG:		return "EMERG";
	case LOG_ALERT:		return "ALERT";
	case LOG_CRIT:		return "CRIT";
	case LOG_ERR:		return "ERR";
	case LOG_WARNING:	return "WARNING";
	case LOG_NOTICE:	return "NOTICE";
	case LOG_INFO:		return "INFO";
	case LOG_DEBUG:		return "DEBUG";
	default:		return "???";
	}
}

void DEBUG(int pri, char *fmt, ...)
{
	int saved_errno = errno;
	va_list ap;

	if (opt_v || pri != LOG_DEBUG) {
		va_start(ap, fmt);
		if (daemonized) {
			vsyslog(pri, fmt, ap);
		} else {
			fprintf(stderr, "[%s] ", log_level(pri));
			vfprintf(stderr, fmt, ap);
		}
		va_end(ap);
	}
	errno = saved_errno;
}
#endif

/* --------- */
__inline__ static int open_sock(void)
{
	return socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
}

static int set_recvpktinfo(int socket)
{
	int on, ret;

	on = 1;

#if defined(IPV6_RECVPKTINFO)
	ret = setsockopt(socket,
			 IPPROTO_IPV6, IPV6_RECVPKTINFO,
			 &on, sizeof(on));
	if (!ret)
		return 0;
# if defined(IPV6_2292PKTINFO)
	ret = setsockopt(socket,
			 IPPROTO_IPV6, IPV6_2292PKTINFO,
			 &on, sizeof(on));
	if (!ret) {
		ipv6_pktinfo = IPV6_2292PKTINFO;
		return 0;
	}

	DEBUG(LOG_ERR, "setsockopt(IPV6_RECVPKTINFO/IPV6_2292PKTINFO): %s\n",
	      strerror(errno));
# else
	DEBUG(LOG_ERR, "setsockopt(IPV6_RECVPKTINFO): %s\n",
	      strerror(errno));
# endif
#else
	ret = setsockopt(socket,
			 IPPROTO_IPV6, IPV6_PKTINFO,
			 &on, sizeof(on));
	if (!ret)
		return 0;

	DEBUG(LOG_ERR, "setsockopt(IPV6_PKTINFO): %s\n",
	      strerror(errno));
#endif

	return -1;
}

__inline__ static int init_sock(int socket)
{
	struct icmp6_filter filter;

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(IPUTILS_NI_ICMP6_QUERY, &filter);
	if (setsockopt(socket,
		       IPPROTO_ICMPV6, ICMP6_FILTER,
		       &filter, sizeof(filter)) < 0) {
		DEBUG(LOG_ERR, "setsockopt(ICMP6_FILTER): %s\n",
		      strerror(errno));
		return -1;
	}

	if (set_recvpktinfo(socket) < 0)
		return -1;

	return 0;
}

/* --------- */
int ni_recv(struct packetcontext *p)
{
	int socket = p->sock;
	struct iovec iov[1];
	struct msghdr msgh;
	char recvcbuf[CMSG_SPACE(sizeof(p->pktinfo))];
	struct cmsghdr *cmsg;
	int cc;

	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = p->query;
	iov[0].iov_len = sizeof(p->query);

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = (struct sockaddr *)&p->addr;
	msgh.msg_namelen = sizeof(p->addr);
	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = recvcbuf;
	msgh.msg_controllen = sizeof(recvcbuf);

	if ((cc = recvmsg(socket, &msgh, 0)) < 0)
		return -1;

	p->querylen = cc;
	p->addrlen = msgh.msg_namelen;

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg;
	     cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    (cmsg->cmsg_type == IPV6_PKTINFO
#if defined(IPV6_2292PKTINFO)
		     || cmsg->cmsg_type == IPV6_2292PKTINFO
#endif
		    )) {
			memcpy(&p->pktinfo, CMSG_DATA(cmsg), sizeof(p->pktinfo));
			break;
		}
	}

	return 0;
}

int ni_send(struct packetcontext *p)
{
	int socket = p->sock;
	struct iovec iov[2];
	char cbuf[CMSG_SPACE(sizeof(p->pktinfo))];
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	int cc;

	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &p->reply;
	iov[0].iov_len = sizeof(p->reply);
	iov[1].iov_base = p->replydata;
	iov[1].iov_len = p->replydatalen;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = (struct sockaddr *)&p->addr;
	msgh.msg_namelen = p->addrlen;
	msgh.msg_iov = iov;
	msgh.msg_iovlen = p->replydata ? 2 : 1;

	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = ipv6_pktinfo;
	cmsg->cmsg_len = CMSG_LEN(sizeof(p->pktinfo));
	memcpy(CMSG_DATA(cmsg), &p->pktinfo, sizeof(p->pktinfo));

	msgh.msg_controllen = cmsg->cmsg_len;

	if (p->delay) {
#if HAVE_NANOSLEEP
		struct timespec ts, rts;
		int err = 0;

		rts.tv_sec  = p->delay / 1000000;
		rts.tv_nsec = (long)(p->delay % 1000000) * 1000;

		do {
			ts = rts;
			err = nanosleep(&ts, &rts);
		} while(err < 0);
#else
		usleep(p->delay);	/*XXX: signal*/
#endif
	}

	cc = sendmsg(socket, &msgh, 0);
	if (cc < 0)
		DEBUG(LOG_DEBUG, "sendmsg(): %s\n", strerror(errno));

	free(p->replydata);
	free(p);

	return cc;
}

/* --------- */
static void sig_handler(int sig)
{
	if (!got_signal && sig)
		DEBUG(LOG_INFO, "singnal(%d) received, quitting.\n", sig);
	got_signal = 1;
}

static void setup_sighandlers(void)
{
	struct sigaction act;
	sigset_t smask;
	sigemptyset(&smask);
	sigaddset(&smask, SIGHUP);
	sigaddset(&smask, SIGINT);
	sigaddset(&smask, SIGQUIT);
	sigaddset(&smask, SIGTERM);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_handler;
	act.sa_mask = smask;

	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

static void set_logfile(void)
{
	setbuf(stderr, NULL);
#if ENABLE_DEBUG
	openlog(NINFOD, 0, LOG_USER);
#endif
}

static void cleanup_pidfile(void)
{
	if (daemonized && opt_p) {
		unlink(opt_p);
		DEBUG(LOG_ERR, "failed to unlink file '%s' : %s\n",
				opt_p, strerror(errno));
	}
}

static FILE *fopen_excl(const char *file)
{
#ifndef __linux__
	int fd;
	FILE *fp;

	fd = open(file, O_CREAT | O_RDWR | O_EXCL,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0)
		return NULL;

	return fdopen(file, "w+");
#else
	return fopen(file, "w+x");
#endif
}

static void do_daemonize(void)
{
	FILE *fp = NULL;
	pid_t pid;

	if (opt_p) {
		if (!access(opt_p, R_OK)) {
			if ((fp = fopen(opt_p, "r"))) {
				if (fscanf(fp, "%d", &pid) != 1) {
					DEBUG(LOG_ERR, "pid file '%s' exists, but read failed.\n",
					      opt_p);
				} else {
					DEBUG(LOG_ERR, "pid file '%s' exists : %d\n",
					      opt_p, pid);
				}
				fclose(fp);
				exit(1);
			}
		}

		fp = fopen_excl(opt_p);
		if (!fp) {
			DEBUG(LOG_ERR, "failed to open file '%s': %s\n",
			      opt_p, strerror(errno));
			exit(1);
		}
	}

	if (daemon(0, 0) < 0) {
		DEBUG(LOG_ERR, "failed to daemon(): %s\n", strerror(errno));
		unlink(opt_p);
		exit(1);
	}
	daemonized = 1;

	if (fp) {
		fprintf(fp, "%d\n", getpid());
		if (close_stream(fp)) {
			unlink(opt_p);
			DEBUG(LOG_ERR, "%s: write failed: %s\n", opt_p, strerror(errno));
			exit(1);
		}
	}
}

/* --------- */
#ifdef HAVE_LIBCAP
static const cap_value_t cap_net_raw = CAP_NET_RAW;
static const cap_value_t cap_setuid =  CAP_SETUID; 
static cap_flag_value_t cap_ok;
#else
static uid_t euid;
#endif

static void limit_capabilities(void)
{
#ifdef HAVE_LIBCAP
	cap_t cap_p, cap_cur_p;

	cap_p = cap_init();
	if (!cap_p) {
		DEBUG(LOG_ERR, "cap_init: %s\n", strerror(errno));
		exit(-1);
	}

	cap_cur_p = cap_get_proc();
	if (!cap_cur_p) {
		DEBUG(LOG_ERR, "cap_get_proc: %s\n", strerror(errno));
		exit(-1);
        }

	/* net_raw + setuid / net_raw */
	cap_get_flag(cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &cap_ok);
	if (cap_ok != CAP_CLEAR) {
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_net_raw, CAP_SET);
		cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap_net_raw, CAP_SET);
	}

	cap_get_flag(cap_cur_p, CAP_SETUID, CAP_PERMITTED, &cap_ok);
	if (cap_ok != CAP_CLEAR)
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_setuid, CAP_SET);

	if (cap_set_proc(cap_p) < 0) {
		DEBUG(LOG_ERR, "cap_set_proc: %s\n", strerror(errno));
		if (errno != EPERM)
			exit(-1);
	}

	if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
		DEBUG(LOG_ERR, "prctl: %s\n", strerror(errno));
		exit(-1);
	}

	cap_free(cap_cur_p);
	cap_free(cap_p);
#else
	euid = geteuid();
#endif
}

static void drop_capabilities(void)
{
#ifdef HAVE_LIBCAP
	cap_t cap_p;

	cap_p = cap_init();
	if (!cap_p) {
		DEBUG(LOG_ERR, "cap_init: %s\n", strerror(errno));
		exit(-1);
	}

	/* setuid / setuid */
	if (cap_ok != CAP_CLEAR) {
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_setuid, CAP_SET);
		cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap_setuid, CAP_SET);

		if (cap_set_proc(cap_p) < 0) {
			DEBUG(LOG_ERR, "cap_set_proc: %s\n", strerror(errno));
			exit(-1);
		}
	}

	if (seteuid(opt_u ? opt_u : getuid()) < 0) {
		DEBUG(LOG_ERR, "setuid: %s\n", strerror(errno));
		exit(-1);
	}

	if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
		DEBUG(LOG_ERR, "prctl: %s\n", strerror(errno));
		exit(-1);
	}

	cap_clear(cap_p);
	if (cap_set_proc(cap_p) < 0) {
		DEBUG(LOG_ERR, "cap_set_proc: %s\n", strerror(errno));
		exit(-1);
	}

	cap_free(cap_p);
#else
	if (setuid(getuid()) < 0) {
		DEBUG(LOG_ERR, "setuid: %s\n", strerror(errno));
		exit(-1);
	}
#endif
}

/* --------- */
static void parse_args(int argc, char **argv)
{
	int c;
	unsigned long val;
	char *ep;

	/* parse options */
	while ((c = getopt(argc, argv, "dhvp:u:V")) != -1) {
		switch(c) {
		case 'd':	/* debug */
			opt_d = 1;
			break;
		case 'v':	/* verbose */
			opt_v = 1;
			break;
		case 'p':
			opt_p = optarg;
			break;
		case 'u':
			val = strtoul(optarg, &ep, 10);
			if (!optarg || *ep) {
				struct passwd *pw = getpwnam(optarg);
				if (!pw) {
					DEBUG(LOG_ERR, "No such user: %s", optarg);
					exit(1);
				}
				opt_u = pw->pw_uid;
			} else
				opt_u = val;
			break;
		case 'V':
			printf(IPUTILS_VERSION("ninfod"));
			exit(0);
		case 'h':	/* help */
		default:
			opt_h = 1;
			break;
		}
	}

	argc -= optind;
#if 0
	argv += optind;
#endif

	if (argc)
		opt_h = 1;
}

static void print_copying(void) {
	fprintf(stderr,
		"Node Information Daemon\n"
		"Copyright (C)2002 USAGI/WIDE Project.  All Rights Reserved.\n"
		"\n"
	);
}

static void print_usage(void) {
	fprintf(stderr, 
		"Usage:\n"
		"  ninfod [options]\n"
		"\nOptions:\n"
		"  -d            debug mode\n"
		"  -h            show help\n"
		"  -p <pidfile>  file to store process-id\n"
		"  -u <user>     run <user>\n"
		"  -v            verbose mode\n"
		"  -V            print version and exit\n"
		"\nFor more details see ninfod(8).\n"
	);
}

/* --------- */
int main (int argc, char **argv)
{
	int sock_errno = 0;

	atexit(close_stdout);
	appname = argv[0];
	set_logfile();

	limit_capabilities();

	sock = open_sock();
	if (sock < 0)
		sock_errno = errno;

	parse_args(argc, argv);

	drop_capabilities();

	if (opt_h || opt_v)
		print_copying();
	if (opt_h) {
		print_usage();
		exit(1);
	}

	if (sock_errno) {
		DEBUG(LOG_ERR, "socket: %s\n", strerror(sock_errno));
		exit(1);
	}

	/* initialize */
	if (init_sock(sock) < 0)
		exit(1);

	setup_sighandlers();
	if (!opt_d)
		do_daemonize();

	init_core(1);

	/* main loop */
	while (!got_signal) {
		struct packetcontext *p;
		struct icmp6_hdr *icmph;
#if ENABLE_DEBUG
		char saddrbuf[NI_MAXHOST];
		int status;
#endif 

		init_core(0);

		p = calloc(1, sizeof(*p));
		if (!p) {
			DEBUG(LOG_WARNING, "%s(): failed to allocate packet context; sleep 1 sec.\n",
			      __func__);
			sleep(1);
			continue;
		}

		while (!got_signal) {
			memset(p, 0, sizeof(*p));
			p->sock = sock;

			if (ni_recv(p) < 0) {
				if (got_signal)
					break;
				if (errno == EAGAIN || errno == EINTR)
					continue;
				/* XXX: syslog */
				continue;
			}
			break;
		}

#if ENABLE_DEBUG
		status = getnameinfo((struct sockaddr *)&p->addr,
				  p->addrlen,
				  saddrbuf, sizeof(saddrbuf),
				  NULL, 0,
				  NI_NUMERICHOST);
		if (status)
			sprintf(saddrbuf, "???");
#endif
		init_core(0);

		if (p->querylen < sizeof(struct icmp6_hdr)) {
			free(p);
#if ENABLE_DEBUG
			DEBUG(LOG_WARNING, "Too short icmp message from %s\n", saddrbuf);
#endif
			continue;
		}

		icmph = (struct icmp6_hdr *)p->query;

		DEBUG(LOG_DEBUG,
		      "type=%d, code=%d, cksum=0x%04x\n",
		      icmph->icmp6_type, icmph->icmp6_code,
		      ntohs(icmph->icmp6_cksum));

		if (icmph->icmp6_type != IPUTILS_NI_ICMP6_QUERY) {
#if ENABLE_DEBUG
			DEBUG(LOG_WARNING,
			      "Strange icmp type %d from %s\n", 
			      icmph->icmp6_type, saddrbuf);
#endif
			free(p);
			continue;
		}

		pr_nodeinfo(p);	/* this frees p */
	}

	cleanup_pidfile();

	exit(0);
}

