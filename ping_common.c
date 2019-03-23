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
#include "iputils_common.h"
#include "ping.h"

#ifndef HZ
#define HZ sysconf(_SC_CLK_TCK)
#endif

int options;

int mark;
int sndbuf;
int ttl;
int rtt;
int rtt_addend;
uint16_t acked;

unsigned char outpack[MAXPACKET];
struct rcvd_table rcvd_tbl;

/* counters */
long npackets;			/* max packets to transmit */
long nreceived;			/* # of packets we got back */
long nrepeats;			/* number of duplicates */
long ntransmitted;		/* sequence # for outbound packets = #sent */
long nchecksum;			/* replies with bad checksum */
long nerrors;			/* icmp errors */
int interval = 1000;		/* interval between packets (msec) */
int preload = 1;
int deadline = 0;		/* time to die */
int lingertime = MAXWAIT * 1000;
struct timeval start_time, cur_time;
volatile int exiting;
volatile int status_snapshot;
int confirm = 0;
volatile int in_pr_addr = 0;	/* pr_addr() is executing */
jmp_buf pr_addr_jmp;

/* Stupid workarounds for bugs/missing functionality in older linuces.
 * confirm_flag fixes refusing service of kernels without MSG_CONFIRM.
 * i.e. for linux-2.2 */
int confirm_flag = MSG_CONFIRM;

/* timing */
int timing;			/* flag to do timing */
long tmin = LONG_MAX;		/* minimum round trip time */
long tmax;			/* maximum round trip time */
/* Message for rpm maintainers: have _shame_. If you want
 * to fix something send the patch to me for sanity checking.
 * "sparcfix" patch is a complete non-sense, apparenly the person
 * prepared it was stoned.
 */
double tsum;			/* sum of all times, for doing average */
double tsum2;
int pipesize = -1;

int datalen = DEFDATALEN;

char *hostname;
int uid;
uid_t euid;
int ident;			/* process id to identify our packets */

static int screen_width = INT_MAX;

#ifdef HAVE_LIBCAP
static cap_value_t cap_raw = CAP_NET_RAW;
static cap_value_t cap_admin = CAP_NET_ADMIN;
#endif

void usage(void)
{
	fprintf(stderr,
		"\nUsage\n"
		"  ping [options] <destination>\n"
		"\nOptions:\n"
		"  <destination>      dns name or ip address\n"
		"  -a                 use audible ping\n"
		"  -A                 use adaptive ping\n"
		"  -B                 sticky source address\n"
		"  -c <count>         stop after <count> replies\n"
		"  -D                 print timestamps\n"
		"  -d                 use SO_DEBUG socket option\n"
		"  -f                 flood ping\n"
		"  -h                 print help and exit\n"
		"  -I <interface>     either interface name or address\n"
		"  -i <interval>      seconds between sending each packet\n"
		"  -L                 suppress loopback of multicast packets\n"
		"  -l <preload>       send <preload> number of packages while waiting replies\n"
		"  -m <mark>          tag the packets going out\n"
		"  -M <pmtud opt>     define mtu discovery, can be one of <do|dont|want>\n"
		"  -n                 no dns name resolution\n"
		"  -O                 report outstanding replies\n"
		"  -p <pattern>       contents of padding byte\n"
		"  -q                 quiet output\n"
		"  -Q <tclass>        use quality of service <tclass> bits\n"
		"  -s <size>          use <size> as number of data bytes to be sent\n"
		"  -S <size>          use <size> as SO_SNDBUF socket option value\n"
		"  -t <ttl>           define time to live\n"
		"  -U                 print user-to-user latency\n"
		"  -v                 verbose output\n"
		"  -V                 print version and exit\n"
		"  -w <deadline>      reply wait <deadline> in seconds\n"
		"  -W <timeout>       time to wait for response\n"
		"\nIPv4 options:\n"
		"  -4                 use IPv4\n"
		"  -b                 allow pinging broadcast\n"
		"  -R                 record route\n"
		"  -T <timestamp>     define timestamp, can be one of <tsonly|tsandaddr|tsprespec>\n"
		"\nIPv6 options:\n"
		"  -6                 use IPv6\n"
		"  -F <flowlabel>     define flow label, default is random\n"
		"  -N <nodeinfo opt>  use icmp6 node info query, try <help> as argument\n"
		"\nFor more details see ping(8).\n"
	);
	exit(2);
}

void limit_capabilities(void)
{
#ifdef HAVE_LIBCAP
	cap_t cap_cur_p;
	cap_t cap_p;
	cap_flag_value_t cap_ok;

	cap_cur_p = cap_get_proc();
	if (!cap_cur_p)
		error(-1, errno, "cap_get_proc");
	cap_p = cap_init();
	if (!cap_p)
		error(-1, errno, "cap_init");
	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_cur_p, CAP_NET_ADMIN, CAP_PERMITTED, &cap_ok);
	if (cap_ok != CAP_CLEAR)
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_admin, CAP_SET);
	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &cap_ok);
	if (cap_ok != CAP_CLEAR)
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &cap_raw, CAP_SET);
	if (cap_set_proc(cap_p) < 0)
		error(-1, errno, "cap_set_proc");
	if (prctl(PR_SET_KEEPCAPS, 1) < 0)
		error(-1, errno, "prctl");
	if (setuid(getuid()) < 0)
		error(-1, errno, "setuid");
	if (prctl(PR_SET_KEEPCAPS, 0) < 0)
		error(-1, errno, "prctl");
	cap_free(cap_p);
	cap_free(cap_cur_p);
#endif
	uid = getuid();
	euid = geteuid();
#ifndef HAVE_LIBCAP
	if (seteuid(uid))
		error(-1, errno, "setuid");
#endif
}

#ifdef HAVE_LIBCAP
int modify_capability(cap_value_t cap, cap_flag_value_t on)
{
	cap_t cap_p = cap_get_proc();
	cap_flag_value_t cap_ok;
	int rc = -1;

	if (!cap_p) {
		error(0, errno, "cap_get_proc");
		goto out;
	}

	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_p, cap, CAP_PERMITTED, &cap_ok);
	if (cap_ok == CAP_CLEAR) {
		rc = on ? -1 : 0;
		goto out;
	}

	cap_set_flag(cap_p, CAP_EFFECTIVE, 1, &cap, on);

	if (cap_set_proc(cap_p) < 0) {
		error(0, errno, "cap_set_proc");
		goto out;
	}

	cap_free(cap_p);
	cap_p = NULL;

	rc = 0;
out:
	if (cap_p)
		cap_free(cap_p);
	return rc;
}
#else
int modify_capability(int on)
{
	if (seteuid(on ? euid : getuid())) {
		error(0, errno, "seteuid");
		return -1;
	}

	return 0;
}
#endif

void drop_capabilities(void)
{
#ifdef HAVE_LIBCAP
	cap_t cap = cap_init();
	if (cap_set_proc(cap) < 0)
		error(-1, errno, "cap_set_proc");
	cap_free(cap);
#else
	if (setuid(getuid()))
		error(-1, errno, "setuid");
#endif
}

/* Fills all the outpack, excluding ICMP header, but _including_
 * timestamp area with supplied pattern.
 */
void fill(char *patp, unsigned char *packet, unsigned packet_size)
{
	int ii, jj;
	unsigned int pat[16];
	char *cp;
	unsigned char *bp = packet + 8;

#ifdef USE_IDN
	setlocale(LC_ALL, "C");
#endif

	for (cp = patp; *cp; cp++) {
		if (!isxdigit(*cp))
			error(2, 0, _("patterns must be specified as hex digits: %s"), cp);
	}
	ii = sscanf(patp,
		    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		    &pat[0], &pat[1], &pat[2], &pat[3], &pat[4], &pat[5],
		    &pat[6], &pat[7], &pat[8], &pat[9], &pat[10], &pat[11],
		    &pat[12], &pat[13], &pat[14], &pat[15]);

	if (ii > 0) {
		unsigned kk;
		for (kk = 0; kk <= packet_size - (8 + ii); kk += ii)
			for (jj = 0; jj < ii; ++jj)
				bp[jj + kk] = pat[jj];
	}
	if (!(options & F_QUIET)) {
		printf(_("PATTERN: 0x"));
		for (jj = 0; jj < ii; ++jj)
			printf("%02x", bp[jj] & 0xFF);
		printf("\n");
	}

#ifdef USE_IDN
	setlocale(LC_ALL, "");
#endif
}

static void sigexit(int signo __attribute__((__unused__)))
{
	exiting = 1;
	if (in_pr_addr)
		longjmp(pr_addr_jmp, 0);
}

static void sigstatus(int signo __attribute__((__unused__)))
{
	status_snapshot = 1;
}

int __schedule_exit(int next)
{
	static unsigned long waittime;
	struct itimerval it;

	if (waittime)
		return next;

	if (nreceived) {
		waittime = 2 * tmax;
		if (waittime < (unsigned long)(1000 * interval))
			waittime = 1000 * interval;
	} else
		waittime = lingertime * 1000;

	if (next < 0 || (unsigned long)next < waittime / 1000)
		next = waittime / 1000;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	it.it_value.tv_sec = waittime / 1000000;
	it.it_value.tv_usec = waittime % 1000000;
	setitimer(ITIMER_REAL, &it, NULL);
	return next;
}

static inline void update_interval(void)
{
	int est = rtt ? rtt / 8 : interval * 1000;

	interval = (est + rtt_addend + 500) / 1000;
	if (uid && interval < MINUSERINTERVAL)
		interval = MINUSERINTERVAL;
}

/*
 * Print timestamp
 */
void print_timestamp(void)
{
	if (options & F_PTIMEOFDAY) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("[%lu.%06lu] ",
		       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
	}
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int pinger(ping_func_set_st *fset, socket_st *sock)
{
	static int oom_count;
	static int tokens;
	int i;

	/* Have we already sent enough? If we have, return an arbitrary positive value. */
	if (exiting || (npackets && ntransmitted >= npackets && !deadline))
		return 1000;

	/* Check that packets < rate*time + preload */
	if (cur_time.tv_sec == 0) {
		gettimeofday(&cur_time, NULL);
		tokens = interval * (preload - 1);
	} else {
		long ntokens;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ntokens = (tv.tv_sec - cur_time.tv_sec) * 1000 +
			  (tv.tv_usec - cur_time.tv_usec) / 1000;
		if (!interval) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			if (ntokens < MININTERVAL && in_flight() >= preload)
				return MININTERVAL - ntokens;
		}
		ntokens += tokens;
		if (ntokens > interval * preload)
			ntokens = interval * preload;
		if (ntokens < interval)
			return interval - ntokens;

		cur_time = tv;
		tokens = ntokens - interval;
	}

	if (options & F_OUTSTANDING) {
		if (ntransmitted > 0 && !rcvd_test(ntransmitted)) {
			print_timestamp();
			printf(_("no answer yet for icmp_seq=%lu\n"), (ntransmitted % MAX_DUP_CHK));
			fflush(stdout);
		}
	}

resend:
	i = fset->send_probe(sock, outpack, sizeof(outpack));

	if (i == 0) {
		oom_count = 0;
		advance_ntransmitted();
		if (!(options & F_QUIET) && (options & F_FLOOD)) {
			/* Very silly, but without this output with
			 * high preload or pipe size is very confusing. */
			if ((preload < screen_width && pipesize < screen_width) ||
			    in_flight() < screen_width)
				write_stdout(".", 1);
		}
		return interval - tokens;
	}

	/* And handle various errors... */
	if (i > 0) {
		/* Apparently, it is some fatal bug. */
		abort();
	} else if (errno == ENOBUFS || errno == ENOMEM) {
		int nores_interval;

		/* Device queue overflow or OOM. Packet is not sent. */
		tokens = 0;
		/* Slowdown. This works only in adaptive mode (option -A) */
		rtt_addend += (rtt < 8 * 50000 ? rtt / 8 : 50000);
		if (options & F_ADAPTIVE)
			update_interval();
		nores_interval = SCHINT(interval / 2);
		if (nores_interval > 500)
			nores_interval = 500;
		oom_count++;
		if (oom_count * nores_interval < lingertime)
			return nores_interval;
		i = 0;
		/* Fall to hard error. It is to avoid complete deadlock
		 * on stuck output device even when dealine was not requested.
		 * Expected timings are screwed up in any case, but we will
		 * exit some day. :-) */
	} else if (errno == EAGAIN) {
		/* Socket buffer is full. */
		tokens += interval;
		return MININTERVAL;
	} else {
		if ((i = fset->receive_error_msg(sock)) > 0) {
			/* An ICMP error arrived. In this case, we've received
			 * an error from sendto(), but we've also received an
			 * ICMP message, which means the packet did in fact
			 * send in some capacity. So, in this odd case, report
			 * the more specific errno as the error, and treat this
			 * as a hard local error. */
			i = 0;
			goto hard_local_error;
		}
		/* Compatibility with old linuces. */
		if (i == 0 && confirm_flag && errno == EINVAL) {
			confirm_flag = 0;
			errno = 0;
		}
		if (!errno)
			goto resend;
	}

hard_local_error:
	/* Hard local error. Pretend we sent packet. */
	advance_ntransmitted();

	if (i == 0 && !(options & F_QUIET)) {
		if (options & F_FLOOD)
			write_stdout("E", 1);
		else
			error(0, errno, "sendmsg");
	}
	tokens = 0;
	return SCHINT(interval);
}

/* Set socket buffers, "alloc" is an estimate of memory taken by single packet. */

void sock_setbufs(socket_st *sock, int alloc)
{
	int rcvbuf, hold;
	socklen_t tmplen = sizeof(hold);

	if (!sndbuf)
		sndbuf = alloc;
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));

	rcvbuf = hold = alloc * preload;
	if (hold < 65536)
		hold = 65536;
	setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold));
	if (getsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *)&hold, &tmplen) == 0) {
		if (hold < rcvbuf)
			error(0, 0, _("WARNING: probably, rcvbuf is not enough to hold preload"));
	}
}

/* Protocol independent setup and parameter checks. */

void setup(socket_st *sock)
{
	int hold;
	struct timeval tv;
	sigset_t sset;

	if ((options & F_FLOOD) && !(options & F_INTERVAL))
		interval = 0;

	if (uid && interval < MINUSERINTERVAL)
		error(2, 0, _("cannot flood; minimal interval allowed for user is %dms"), MINUSERINTERVAL);

	if (interval >= INT_MAX / preload)
		error(2, 0, _("illegal preload and/or interval: %d"), interval);

	hold = 1;
	if (options & F_SO_DEBUG)
		setsockopt(sock->fd, SOL_SOCKET, SO_DEBUG, (char *)&hold, sizeof(hold));
	if (options & F_SO_DONTROUTE)
		setsockopt(sock->fd, SOL_SOCKET, SO_DONTROUTE, (char *)&hold, sizeof(hold));

#ifdef SO_TIMESTAMP
	if (!(options & F_LATENCY)) {
		int on = 1;
		if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
			error(0, 0, _("Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP"));
	}
#endif
#ifdef SO_MARK
	if (options & F_MARK) {
		int ret;
		int errno_save;

		enable_capability_admin();
		ret = setsockopt(sock->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
		errno_save = errno;
		disable_capability_admin();

		if (ret == -1) {
			/* Do not exit, old kernels do not support mark. */
			error(0, errno_save, _("Warning: Failed to set mark: %d"), mark);
		}
	}
#endif

	/* Set some SNDTIMEO to prevent blocking forever
	 * on sends, when device is too slow or stalls. Just put limit
	 * of one second, or "interval", if it is less.
	 */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (interval < 1000) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000 * SCHINT(interval);
	}
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

	/* Set RCVTIMEO to "interval". Note, it is just an optimization
	 * allowing to avoid redundant poll(). */
	tv.tv_sec = SCHINT(interval) / 1000;
	tv.tv_usec = 1000 * (SCHINT(interval) % 1000);
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)))
		options |= F_FLOOD_POLL;

	if (!(options & F_PINGFILLED)) {
		int i;
		unsigned char *p = outpack + 8;

		/* Do not forget about case of small datalen, fill timestamp area too! */
		for (i = 0; i < datalen; ++i)
			*p++ = i;
	}

	if (sock->socktype == SOCK_RAW)
		ident = htons(getpid() & 0xFFFF);

	set_signal(SIGINT, sigexit);
	set_signal(SIGALRM, sigexit);
	set_signal(SIGQUIT, sigstatus);

	sigemptyset(&sset);
	sigprocmask(SIG_SETMASK, &sset, NULL);

	gettimeofday(&start_time, NULL);

	if (deadline) {
		struct itimerval it;

		it.it_interval.tv_sec = 0;
		it.it_interval.tv_usec = 0;
		it.it_value.tv_sec = deadline;
		it.it_value.tv_usec = 0;
		setitimer(ITIMER_REAL, &it, NULL);
	}

	if (isatty(STDOUT_FILENO)) {
		struct winsize w;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				screen_width = w.ws_col;
		}
	}
}

/*
 * Return 0 if pattern in payload point to be ptr did not match the pattern that was sent  
 */
int contains_pattern_in_payload(uint8_t *ptr)
{
	int i;
	uint8_t *cp, *dp;
 
	/* check the data */
	cp = ((u_char *)ptr) + sizeof(struct timeval);
	dp = &outpack[8 + sizeof(struct timeval)];
	for (i = sizeof(struct timeval); i < datalen; ++i, ++cp, ++dp) {
		if (*cp != *dp)
			return 0;
	}
	return 1;
}

void main_loop(ping_func_set_st *fset, socket_st *sock, uint8_t *packet, int packlen)
{
	char addrbuf[128];
	char ans_data[4096];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *c;
	int cc;
	int next;
	int polling;
	int recv_error;

	iov.iov_base = (char *)packet;

	for (;;) {
		/* Check exit conditions. */
		if (exiting)
			break;
		if (npackets && nreceived + nerrors >= npackets)
			break;
		if (deadline && nerrors)
			break;
		/* Check for and do special actions. */
		if (status_snapshot)
			status();

		/* Send probes scheduled to this time. */
		do {
			next = pinger(fset, sock);
			next = schedule_exit(next);
		} while (next <= 0);

		/* "next" is time to send next probe, if positive.
		 * If next<=0 send now or as soon as possible. */

		/* Technical part. Looks wicked. Could be dropped,
		 * if everyone used the newest kernel. :-)
		 * Its purpose is:
		 * 1. Provide intervals less than resolution of scheduler.
		 *    Solution: spinning.
		 * 2. Avoid use of poll(), when recvmsg() can provide
		 *    timed waiting (SO_RCVTIMEO). */
		polling = 0;
		recv_error = 0;
		if ((options & (F_ADAPTIVE | F_FLOOD_POLL)) || next < SCHINT(interval)) {
			int recv_expected = in_flight();

			/* If we are here, recvmsg() is unable to wait for
			 * required timeout. */
			if (1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
				/* Very short timeout... So, if we wait for
				 * something, we sleep for MININTERVAL.
				 * Otherwise, spin! */
				if (recv_expected) {
					next = MININTERVAL;
				} else {
					next = 0;
					/* When spinning, no reasons to poll.
					 * Use nonblocking recvmsg() instead. */
					polling = MSG_DONTWAIT;
					/* But yield yet. */
					sched_yield();
				}
			}

			if (!polling &&
			    ((options & (F_ADAPTIVE | F_FLOOD_POLL)) || interval)) {
				struct pollfd pset;
				pset.fd = sock->fd;
				pset.events = POLLIN;
				pset.revents = 0;
				if (poll(&pset, 1, next) < 1 ||
				    !(pset.revents & (POLLIN | POLLERR)))
					continue;
				polling = MSG_DONTWAIT;
				recv_error = pset.revents & POLLERR;
			}
		}

		for (;;) {
			struct timeval *recv_timep = NULL;
			struct timeval recv_time;
			int not_ours = 0; /* Raw socket can receive messages
					   * destined to other running pings. */

			iov.iov_len = packlen;
			memset(&msg, 0, sizeof(msg));
			msg.msg_name = addrbuf;
			msg.msg_namelen = sizeof(addrbuf);
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = ans_data;
			msg.msg_controllen = sizeof(ans_data);

			cc = recvmsg(sock->fd, &msg, polling);
			polling = MSG_DONTWAIT;

			if (cc < 0) {
				/* If there was a POLLERR and there is no packet
				 * on the socket, try to read the error queue.
				 * Otherwise, give up.
				 */
				if ((errno == EAGAIN && !recv_error) ||
				    errno == EINTR)
					break;
				recv_error = 0;
				if (!fset->receive_error_msg(sock)) {
					if (errno) {
						error(0, errno, "recvmsg");
						break;
					}
					not_ours = 1;
				}
			} else {

#ifdef SO_TIMESTAMP
				for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
					if (c->cmsg_level != SOL_SOCKET ||
					    c->cmsg_type != SO_TIMESTAMP)
						continue;
					if (c->cmsg_len < CMSG_LEN(sizeof(struct timeval)))
						continue;
					recv_timep = (struct timeval *)CMSG_DATA(c);
				}
#endif

				if ((options & F_LATENCY) || recv_timep == NULL) {
					if ((options & F_LATENCY) ||
					    ioctl(sock->fd, SIOCGSTAMP, &recv_time))
						gettimeofday(&recv_time, NULL);
					recv_timep = &recv_time;
				}

				not_ours = fset->parse_reply(sock, &msg, cc, addrbuf, recv_timep);
			}

			/* See? ... someone runs another ping on this host. */
			if (not_ours && sock->socktype == SOCK_RAW)
				fset->install_filter(sock);

			/* If nothing is in flight, "break" returns us to pinger. */
			if (in_flight() == 0)
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	finish();
}

int gather_statistics(uint8_t *icmph, int icmplen,
		      int cc, uint16_t seq, int hops,
		      int csfailed, struct timeval *tv, char *from,
		      void (*pr_reply)(uint8_t *icmph, int cc))
{
	int dupflag = 0;
	long triptime = 0;
	uint8_t *ptr = icmph + icmplen;

	++nreceived;
	if (!csfailed)
		acknowledge(seq);

	if (timing && cc >= (int)(8 + sizeof(struct timeval))) {
		struct timeval tmp_tv;
		memcpy(&tmp_tv, ptr, sizeof(tmp_tv));

restamp:
		tvsub(tv, &tmp_tv);
		triptime = tv->tv_sec * 1000000 + tv->tv_usec;
		if (triptime < 0) {
			error(0, 0, _("Warning: time of day goes back (%ldus), taking countermeasures"), triptime);
			triptime = 0;
			if (!(options & F_LATENCY)) {
				gettimeofday(tv, NULL);
				options |= F_LATENCY;
				goto restamp;
			}
		}
		if (!csfailed) {
			tsum += triptime;
			tsum2 += (long long)triptime *(long long)triptime;
			if (triptime < tmin)
				tmin = triptime;
			if (triptime > tmax)
				tmax = triptime;
			if (!rtt)
				rtt = triptime * 8;
			else
				rtt += triptime - rtt / 8;
			if (options & F_ADAPTIVE)
				update_interval();
		}
	}

	if (csfailed) {
		++nchecksum;
		--nreceived;
	} else if (rcvd_test(seq)) {
		++nrepeats;
		--nreceived;
		dupflag = 1;
	} else {
		rcvd_set(seq);
		dupflag = 0;
	}
	confirm = confirm_flag;

	if (options & F_QUIET)
		return 1;

	if (options & F_FLOOD) {
		if (!csfailed)
			write_stdout("\b \b", 3);
		else
			write_stdout("\bC", 2);
	} else {
		int i;
		uint8_t *cp, *dp;

		print_timestamp();
		printf(_("%d bytes from %s:"), cc, from);

		if (pr_reply)
			pr_reply(icmph, cc);

		if (hops >= 0)
			printf(_(" ttl=%d"), hops);

		if (cc < datalen + 8) {
			printf(_(" (truncated)\n"));
			return 1;
		}
		if (timing) {
			if (triptime >= 100000)
				printf(_(" time=%ld ms"), (triptime + 500) / 1000);
			else if (triptime >= 10000)
				printf(_(" time=%ld.%01ld ms"), (triptime + 50) / 1000,
				       ((triptime + 50) % 1000) / 100);
			else if (triptime >= 1000)
				printf(_(" time=%ld.%02ld ms"), (triptime + 5) / 1000,
				       ((triptime + 5) % 1000) / 10);
			else
				printf(_(" time=%ld.%03ld ms"), triptime / 1000,
				       triptime % 1000);
		}
		if (dupflag)
			printf(_(" (DUP!)"));
		if (csfailed)
			printf(_(" (BAD CHECKSUM!)"));

		/* check the data */
		cp = ((unsigned char *)ptr) + sizeof(struct timeval);
		dp = &outpack[8 + sizeof(struct timeval)];
		for (i = sizeof(struct timeval); i < datalen; ++i, ++cp, ++dp) {
			if (*cp != *dp) {
				printf(_("\nwrong data byte #%d should be 0x%x but was 0x%x"),
				       i, *dp, *cp);
				cp = (unsigned char *)ptr + sizeof(struct timeval);
				for (i = sizeof(struct timeval); i < datalen; ++i, ++cp) {
					if ((i % 32) == sizeof(struct timeval))
						printf("\n#%d\t", i);
					printf("%x ", *cp);
				}
				break;
			}
		}
	}
	return 0;
}

static long llsqrt(long long a)
{
	long long prev = LLONG_MAX;
	long long x = a;

	if (x > 0) {
		while (x < prev) {
			prev = x;
			x = (x + (a / x)) / 2;
		}
	}

	return (long)x;
}

/*
 * finish --
 *	Print out statistics, and give up.
 */
void finish(void)
{
	struct timeval tv = cur_time;
	char *comma = "";

	tvsub(&tv, &start_time);

	putchar('\n');
	fflush(stdout);
	printf(_("--- %s ping statistics ---\n"), hostname);
	printf(_("%ld packets transmitted, "), ntransmitted);
	printf(_("%ld received"), nreceived);
	if (nrepeats)
		printf(_(", +%ld duplicates"), nrepeats);
	if (nchecksum)
		printf(_(", +%ld corrupted"), nchecksum);
	if (nerrors)
		printf(_(", +%ld errors"), nerrors);

	if (ntransmitted) {
#ifdef USE_IDN
		setlocale(LC_ALL, "C");
#endif
		printf(_(", %g%% packet loss"),
		       (float)((((long long)(ntransmitted - nreceived)) * 100.0) / ntransmitted));
		printf(_(", time %ldms"), 1000 * tv.tv_sec + (tv.tv_usec + 500) / 1000);
	}

	putchar('\n');

	if (nreceived && timing) {
		double tmdev;
		long total = nreceived + nrepeats;
		long tmavg = tsum / total;
		long long tmvar;

		if (tsum < INT_MAX)
			/* This slightly clumsy computation order is important to avoid
			 * integer rounding errors for small ping times. */
			tmvar = (tsum2 - ((tsum * tsum) / total)) / total;
		else
			tmvar = (tsum2 / total) - (tmavg * tmavg);

		tmdev = llsqrt(tmvar);

		printf(_("rtt min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms"),
		       (long)tmin / 1000, (long)tmin % 1000,
		       (unsigned long)(tmavg / 1000), (long)(tmavg % 1000),
		       (long)tmax / 1000, (long)tmax % 1000,
		       (long)tmdev / 1000, (long)tmdev % 1000);
		comma = ", ";
	}
	if (pipesize > 1) {
		printf(_("%spipe %d"), comma, pipesize);
		comma = ", ";
	}

	if (nreceived && (!interval || (options & (F_FLOOD | F_ADAPTIVE))) && ntransmitted > 1) {
		int ipg = (1000000 * (long long)tv.tv_sec + tv.tv_usec) / (ntransmitted - 1);

		printf(_("%sipg/ewma %d.%03d/%d.%03d ms"),
		       comma, ipg / 1000, ipg % 1000, rtt / 8000, (rtt / 8) % 1000);
	}
	putchar('\n');
	exit(!nreceived || (deadline && nreceived < npackets));
}

void status(void)
{
	int loss = 0;
	long tavg = 0;

	status_snapshot = 0;

	if (ntransmitted)
		loss = (((long long)(ntransmitted - nreceived)) * 100) / ntransmitted;

	fprintf(stderr, "\r");
	fprintf(stderr, _("%ld/%ld packets, %d%% loss"), nreceived, ntransmitted, loss);

	if (nreceived && timing) {
		tavg = tsum / (nreceived + nrepeats);

		fprintf(stderr, _(", min/avg/ewma/max = %ld.%03ld/%lu.%03ld/%d.%03d/%ld.%03ld ms"),
			(long)tmin / 1000, (long)tmin % 1000,
			tavg / 1000, tavg % 1000,
			rtt / 8000, (rtt / 8) % 1000, (long)tmax / 1000, (long)tmax % 1000);
	}
	fprintf(stderr, "\n");
}

inline int is_ours(socket_st * sock, uint16_t id)
{
	return sock->socktype == SOCK_DGRAM || id == ident;
}
