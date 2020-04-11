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

#ifndef HAVE_LIBCAP
static uid_t euid;
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

void limit_capabilities(struct ping_rts *rts)
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
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &rts->cap_admin, CAP_SET);
	cap_ok = CAP_CLEAR;
	cap_get_flag(cap_cur_p, CAP_NET_RAW, CAP_PERMITTED, &cap_ok);
	if (cap_ok != CAP_CLEAR)
		cap_set_flag(cap_p, CAP_PERMITTED, 1, &rts->cap_raw, CAP_SET);
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
#else
	euid = geteuid();
#endif
	rts->uid = getuid();
#ifndef HAVE_LIBCAP
	if (seteuid(rts->uid))
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
void fill(struct ping_rts *rts, char *patp, unsigned char *packet, size_t packet_size)
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
		size_t kk;
		size_t max = packet_size < (size_t)ii + 8 ? 0 : packet_size - (size_t)ii + 8;

		for (kk = 0; kk <= max; kk += ii)
			for (jj = 0; jj < ii; ++jj)
				bp[jj + kk] = pat[jj];
	}
	if (!rts->opt_quiet) {
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
	global_rts->exiting = 1;
	if (global_rts->in_pr_addr)
		longjmp(global_rts->pr_addr_jmp, 0);
}

static void sigstatus(int signo __attribute__((__unused__)))
{
	global_rts->status_snapshot = 1;
}

int __schedule_exit(int next)
{
	static unsigned long waittime;
	struct itimerval it;

	if (waittime)
		return next;

	if (global_rts->nreceived) {
		waittime = 2 * global_rts->tmax;
		if (waittime < 1000 * (unsigned long)global_rts->interval)
			waittime = 1000 * global_rts->interval;
	} else
		waittime = global_rts->lingertime * 1000;

	if (next < 0 || (unsigned long)next < waittime / 1000)
		next = waittime / 1000;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	it.it_value.tv_sec = waittime / 1000000;
	it.it_value.tv_usec = waittime % 1000000;
	setitimer(ITIMER_REAL, &it, NULL);
	return next;
}

static inline void update_interval(struct ping_rts *rts)
{
	int est = rts->rtt ? rts->rtt / 8 : rts->interval * 1000;

	rts->interval = (est + rts->rtt_addend + 500) / 1000;
	if (rts->uid && rts->interval < MINUSERINTERVAL)
		rts->interval = MINUSERINTERVAL;
}

/*
 * Print timestamp
 */
void print_timestamp(struct ping_rts *rts)
{
	if (rts->opt_ptimeofday) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		printf("[%lu.%06lu] ",
		       (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
	}
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is a random number,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int pinger(struct ping_rts *rts, ping_func_set_st *fset, socket_st *sock)
{
	static int oom_count;
	static int tokens;
	int i;

	/* Have we already sent enough? If we have, return an arbitrary positive value. */
	if (rts->exiting || (rts->npackets && rts->ntransmitted >= rts->npackets && !rts->deadline))
		return 1000;

	/* Check that packets < rate*time + preload */
	if (rts->cur_time.tv_sec == 0) {
		gettimeofday(&rts->cur_time, NULL);
		tokens = rts->interval * (rts->preload - 1);
	} else {
		long ntokens, tmp;
		struct timeval tv;

		gettimeofday(&tv, NULL);
		ntokens = (tv.tv_sec - rts->cur_time.tv_sec) * 1000 +
			  (tv.tv_usec - rts->cur_time.tv_usec) / 1000;
		if (!rts->interval) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			if (ntokens < MININTERVAL && in_flight(rts) >= rts->preload)
				return MININTERVAL - ntokens;
		}
		ntokens += tokens;
		tmp = (long)rts->interval * (long)rts->preload;
		if (tmp < ntokens)
			ntokens = tmp;
		if (ntokens < rts->interval)
			return rts->interval - ntokens;

		rts->cur_time = tv;
		tokens = ntokens - rts->interval;
	}

	if (rts->opt_outstanding) {
		if (rts->ntransmitted > 0 && !rcvd_test(rts, rts->ntransmitted)) {
			print_timestamp(rts);
			printf(_("no answer yet for icmp_seq=%lu\n"), (rts->ntransmitted % MAX_DUP_CHK));
			fflush(stdout);
		}
	}

resend:
	i = fset->send_probe(rts, sock, rts->outpack, sizeof(rts->outpack));

	if (i == 0) {
		oom_count = 0;
		advance_ntransmitted(rts);
		if (!rts->opt_quiet && rts->opt_flood) {
			/* Very silly, but without this output with
			 * high preload or pipe size is very confusing. */
			if ((rts->preload < rts->screen_width && rts->pipesize < rts->screen_width) ||
			    in_flight(rts) < rts->screen_width)
				write_stdout(".", 1);
		}
		return rts->interval - tokens;
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
		rts->rtt_addend += (rts->rtt < 8 * 50000 ? rts->rtt / 8 : 50000);
		if (rts->opt_adaptive)
			update_interval(rts);
		nores_interval = SCHINT(rts->interval / 2);
		if (nores_interval > 500)
			nores_interval = 500;
		oom_count++;
		if (oom_count * nores_interval < rts->lingertime)
			return nores_interval;
		i = 0;
		/* Fall to hard error. It is to avoid complete deadlock
		 * on stuck output device even when dealine was not requested.
		 * Expected timings are screwed up in any case, but we will
		 * exit some day. :-) */
	} else if (errno == EAGAIN) {
		/* Socket buffer is full. */
		tokens += rts->interval;
		return MININTERVAL;
	} else {
		if ((i = fset->receive_error_msg(rts, sock)) > 0) {
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
		if (i == 0 && rts->confirm_flag && errno == EINVAL) {
			rts->confirm_flag = 0;
			errno = 0;
		}
		if (!errno)
			goto resend;
	}

hard_local_error:
	/* Hard local error. Pretend we sent packet. */
	advance_ntransmitted(rts);

	if (i == 0 && !rts->opt_quiet) {
		if (rts->opt_flood)
			write_stdout("E", 1);
		else
			error(0, errno, "sendmsg");
	}
	tokens = 0;
	return SCHINT(rts->interval);
}

/* Set socket buffers, "alloc" is an estimate of memory taken by single packet. */

void sock_setbufs(struct ping_rts *rts, socket_st *sock, int alloc)
{
	int rcvbuf, hold;
	socklen_t tmplen = sizeof(hold);

	if (!rts->sndbuf)
		rts->sndbuf = alloc;
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, (char *)&rts->sndbuf, sizeof(rts->sndbuf));

	rcvbuf = hold = alloc * rts->preload;
	if (hold < 65536)
		hold = 65536;
	setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *)&hold, sizeof(hold));
	if (getsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, (char *)&hold, &tmplen) == 0) {
		if (hold < rcvbuf)
			error(0, 0, _("WARNING: probably, rcvbuf is not enough to hold preload"));
	}
}

/* Protocol independent setup and parameter checks. */

void setup(struct ping_rts *rts, socket_st *sock)
{
	int hold;
	struct timeval tv;
	sigset_t sset;

	if (rts->opt_flood && !rts->opt_interval)
		rts->interval = 0;

	if (rts->uid && rts->interval < MINUSERINTERVAL)
		error(2, 0, _("cannot flood; minimal interval allowed for user is %dms"), MINUSERINTERVAL);

	if (rts->interval >= INT_MAX / rts->preload)
		error(2, 0, _("illegal preload and/or interval: %d"), rts->interval);

	hold = 1;
	if (rts->opt_so_debug)
		setsockopt(sock->fd, SOL_SOCKET, SO_DEBUG, (char *)&hold, sizeof(hold));
	if (rts->opt_so_dontroute)
		setsockopt(sock->fd, SOL_SOCKET, SO_DONTROUTE, (char *)&hold, sizeof(hold));

#ifdef SO_TIMESTAMP
	if (!rts->opt_latency) {
		int on = 1;
		if (setsockopt(sock->fd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on)))
			error(0, 0, _("Warning: no SO_TIMESTAMP support, falling back to SIOCGSTAMP"));
	}
#endif
#ifdef SO_MARK
	if (rts->opt_mark) {
		int ret;
		int errno_save;

		enable_capability_admin();
		ret = setsockopt(sock->fd, SOL_SOCKET, SO_MARK, &rts->mark, sizeof(rts->mark));
		errno_save = errno;
		disable_capability_admin();

		if (ret == -1) {
			/* Do not exit, old kernels do not support mark. */
			error(0, errno_save, _("Warning: Failed to set mark: %d"), rts->mark);
		}
	}
#endif

	/* Set some SNDTIMEO to prevent blocking forever
	 * on sends, when device is too slow or stalls. Just put limit
	 * of one second, or "interval", if it is less.
	 */
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	if (rts->interval < 1000) {
		tv.tv_sec = 0;
		tv.tv_usec = 1000 * SCHINT(rts->interval);
	}
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

	/* Set RCVTIMEO to "interval". Note, it is just an optimization
	 * allowing to avoid redundant poll(). */
	tv.tv_sec = SCHINT(rts->interval) / 1000;
	tv.tv_usec = 1000 * (SCHINT(rts->interval) % 1000);
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)))
		rts->opt_flood_poll = 1;

	if (!rts->opt_pingfilled) {
		size_t i;
		unsigned char *p = rts->outpack + 8;

		/* Do not forget about case of small datalen, fill timestamp area too! */
		for (i = 0; i < rts->datalen; ++i)
			*p++ = i;
	}

	if (sock->socktype == SOCK_RAW)
		rts->ident = rand() & 0xFFFF;

	set_signal(SIGINT, sigexit);
	set_signal(SIGALRM, sigexit);
	set_signal(SIGQUIT, sigstatus);

	sigemptyset(&sset);
	sigprocmask(SIG_SETMASK, &sset, NULL);

	gettimeofday(&rts->start_time, NULL);

	if (rts->deadline) {
		struct itimerval it;

		it.it_interval.tv_sec = 0;
		it.it_interval.tv_usec = 0;
		it.it_value.tv_sec = rts->deadline;
		it.it_value.tv_usec = 0;
		setitimer(ITIMER_REAL, &it, NULL);
	}

	if (isatty(STDOUT_FILENO)) {
		struct winsize w;

		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1) {
			if (w.ws_col > 0)
				rts->screen_width = w.ws_col;
		}
	}
}

/*
 * Return 0 if pattern in payload point to be ptr did not match the pattern that was sent  
 */
int contains_pattern_in_payload(struct ping_rts *rts, uint8_t *ptr)
{
	size_t i;
	uint8_t *cp, *dp;
 
	/* check the data */
	cp = ((u_char *)ptr) + sizeof(struct timeval);
	dp = &rts->outpack[8 + sizeof(struct timeval)];
	for (i = sizeof(struct timeval); i < rts->datalen; ++i, ++cp, ++dp) {
		if (*cp != *dp)
			return 0;
	}
	return 1;
}

int main_loop(struct ping_rts *rts, ping_func_set_st *fset, socket_st *sock,
	      uint8_t *packet, int packlen)
{
	char addrbuf[128];
	char ans_data[4096];
	struct iovec iov;
	struct msghdr msg;
	int cc;
	int next;
	int polling;
	int recv_error;

	iov.iov_base = (char *)packet;

	for (;;) {
		/* Check exit conditions. */
		if (rts->exiting)
			break;
		if (rts->npackets && rts->nreceived + rts->nerrors >= rts->npackets)
			break;
		if (rts->deadline && rts->nerrors)
			break;
		/* Check for and do special actions. */
		if (rts->status_snapshot)
			status(rts);

		/* Send probes scheduled to this time. */
		do {
			next = pinger(rts, fset, sock);
			next = schedule_exit(rts, next);
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
		if (rts->opt_adaptive || rts->opt_flood_poll || next < SCHINT(rts->interval)) {
			int recv_expected = in_flight(rts);

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
			    (rts->opt_adaptive || rts->opt_flood_poll || rts->interval)) {
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
				if (!fset->receive_error_msg(rts, sock)) {
					if (errno) {
						error(0, errno, "recvmsg");
						break;
					}
					not_ours = 1;
				}
			} else {

#ifdef SO_TIMESTAMP
				struct cmsghdr *c;

				for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
					if (c->cmsg_level != SOL_SOCKET ||
					    c->cmsg_type != SO_TIMESTAMP)
						continue;
					if (c->cmsg_len < CMSG_LEN(sizeof(struct timeval)))
						continue;
					recv_timep = (struct timeval *)CMSG_DATA(c);
				}
#endif

				if (rts->opt_latency || recv_timep == NULL) {
					if (rts->opt_latency ||
					    ioctl(sock->fd, SIOCGSTAMP, &recv_time))
						gettimeofday(&recv_time, NULL);
					recv_timep = &recv_time;
				}

				not_ours = fset->parse_reply(rts, sock, &msg, cc, addrbuf, recv_timep);
			}

			/* See? ... someone runs another ping on this host. */
			if (not_ours && sock->socktype == SOCK_RAW)
				fset->install_filter(rts, sock);

			/* If nothing is in flight, "break" returns us to pinger. */
			if (in_flight(rts) == 0)
				break;

			/* Otherwise, try to recvmsg() again. recvmsg()
			 * is nonblocking after the first iteration, so that
			 * if nothing is queued, it will receive EAGAIN
			 * and return to pinger. */
		}
	}
	return finish(rts);
}

int gather_statistics(struct ping_rts *rts, uint8_t *icmph, int icmplen,
		      int cc, uint16_t seq, int hops,
		      int csfailed, struct timeval *tv, char *from,
		      void (*pr_reply)(uint8_t *icmph, int cc), int multicast)
{
	int dupflag = 0;
	long triptime = 0;
	uint8_t *ptr = icmph + icmplen;

	++rts->nreceived;
	if (!csfailed)
		acknowledge(rts, seq);

	if (rts->timing && cc >= (int)(8 + sizeof(struct timeval))) {
		struct timeval tmp_tv;
		memcpy(&tmp_tv, ptr, sizeof(tmp_tv));

restamp:
		tvsub(tv, &tmp_tv);
		triptime = tv->tv_sec * 1000000 + tv->tv_usec;
		if (triptime < 0) {
			error(0, 0, _("Warning: time of day goes back (%ldus), taking countermeasures"), triptime);
			triptime = 0;
			if (!rts->opt_latency) {
				gettimeofday(tv, NULL);
				rts->opt_latency = 1;
				goto restamp;
			}
		}
		if (!csfailed) {
			rts->tsum += triptime;
			rts->tsum2 += (double)((long long)triptime * (long long)triptime);
			if (triptime < rts->tmin)
				rts->tmin = triptime;
			if (triptime > rts->tmax)
				rts->tmax = triptime;
			if (!rts->rtt)
				rts->rtt = triptime * 8;
			else
				rts->rtt += triptime - rts->rtt / 8;
			if (rts->opt_adaptive)
				update_interval(rts);
		}
	}

	if (csfailed) {
		++rts->nchecksum;
		--rts->nreceived;
	} else if (rcvd_test(rts, seq)) {
		++rts->nrepeats;
		--rts->nreceived;
		dupflag = 1;
	} else {
		rcvd_set(rts, seq);
		dupflag = 0;
	}
	rts->confirm = rts->confirm_flag;

	if (rts->opt_quiet)
		return 1;

	if (rts->opt_flood) {
		if (!csfailed)
			write_stdout("\b \b", 3);
		else
			write_stdout("\bC", 2);
	} else {
		size_t i;
		uint8_t *cp, *dp;

		print_timestamp(rts);
		printf(_("%d bytes from %s:"), cc, from);

		if (pr_reply)
			pr_reply(icmph, cc);

		if (hops >= 0)
			printf(_(" ttl=%d"), hops);

		if ((size_t)cc < rts->datalen + 8) {
			printf(_(" (truncated)\n"));
			return 1;
		}
		if (rts->timing) {
			if (triptime >= 100000 - 50)
				printf(_(" time=%ld ms"), (triptime + 500) / 1000);
			else if (triptime >= 10000 - 5)
				printf(_(" time=%ld.%01ld ms"), (triptime + 50) / 1000,
				       ((triptime + 50) % 1000) / 100);
			else if (triptime >= 1000)
				printf(_(" time=%ld.%02ld ms"), (triptime + 5) / 1000,
				       ((triptime + 5) % 1000) / 10);
			else
				printf(_(" time=%ld.%03ld ms"), triptime / 1000,
				       triptime % 1000);
		}
		if (dupflag && (!multicast || rts->opt_verbose))
			printf(_(" (DUP!)"));
		if (csfailed)
			printf(_(" (BAD CHECKSUM!)"));

		/* check the data */
		cp = ((unsigned char *)ptr) + sizeof(struct timeval);
		dp = &rts->outpack[8 + sizeof(struct timeval)];
		for (i = sizeof(struct timeval); i < rts->datalen; ++i, ++cp, ++dp) {
			if (*cp != *dp) {
				printf(_("\nwrong data byte #%zu should be 0x%x but was 0x%x"),
				       i, *dp, *cp);
				cp = (unsigned char *)ptr + sizeof(struct timeval);
				for (i = sizeof(struct timeval); i < rts->datalen; ++i, ++cp) {
					if ((i % 32) == sizeof(struct timeval))
						printf("\n#%zu\t", i);
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
int finish(struct ping_rts *rts)
{
	struct timeval tv = rts->cur_time;
	char *comma = "";

	tvsub(&tv, &rts->start_time);

	putchar('\n');
	fflush(stdout);
	printf(_("--- %s ping statistics ---\n"), rts->hostname);
	printf(_("%ld packets transmitted, "), rts->ntransmitted);
	printf(_("%ld received"), rts->nreceived);
	if (rts->nrepeats)
		printf(_(", +%ld duplicates"), rts->nrepeats);
	if (rts->nchecksum)
		printf(_(", +%ld corrupted"), rts->nchecksum);
	if (rts->nerrors)
		printf(_(", +%ld errors"), rts->nerrors);

	if (rts->ntransmitted) {
#ifdef USE_IDN
		setlocale(LC_ALL, "C");
#endif
		printf(_(", %g%% packet loss"),
		       (float)((((long long)(rts->ntransmitted - rts->nreceived)) * 100.0) / rts->ntransmitted));
		printf(_(", time %ldms"), 1000 * tv.tv_sec + (tv.tv_usec + 500) / 1000);
	}

	putchar('\n');

	if (rts->nreceived && rts->timing) {
		double tmdev;
		long total = rts->nreceived + rts->nrepeats;
		long tmavg = rts->tsum / total;
		long long tmvar;

		if (rts->tsum < INT_MAX)
			/* This slightly clumsy computation order is important to avoid
			 * integer rounding errors for small ping times. */
			tmvar = (rts->tsum2 - ((rts->tsum * rts->tsum) / total)) / total;
		else
			tmvar = (rts->tsum2 / total) - (tmavg * tmavg);

		tmdev = llsqrt(tmvar);

		printf(_("rtt min/avg/max/mdev = %ld.%03ld/%lu.%03ld/%ld.%03ld/%ld.%03ld ms"),
		       (long)rts->tmin / 1000, (long)rts->tmin % 1000,
		       (unsigned long)(tmavg / 1000), (long)(tmavg % 1000),
		       (long)rts->tmax / 1000, (long)rts->tmax % 1000,
		       (long)tmdev / 1000, (long)tmdev % 1000);
		comma = ", ";
	}
	if (rts->pipesize > 1) {
		printf(_("%spipe %d"), comma, rts->pipesize);
		comma = ", ";
	}

	if (rts->nreceived && (!rts->interval || rts->opt_flood || rts->opt_adaptive) && rts->ntransmitted > 1) {
		int ipg = (1000000 * (long long)tv.tv_sec + tv.tv_usec) / (rts->ntransmitted - 1);

		printf(_("%sipg/ewma %d.%03d/%d.%03d ms"),
		       comma, ipg / 1000, ipg % 1000, rts->rtt / 8000, (rts->rtt / 8) % 1000);
	}
	putchar('\n');
	return (!rts->nreceived || (rts->deadline && rts->nreceived < rts->npackets));
}

void status(struct ping_rts *rts)
{
	int loss = 0;
	long tavg = 0;

	rts->status_snapshot = 0;

	if (rts->ntransmitted)
		loss = (((long long)(rts->ntransmitted - rts->nreceived)) * 100) / rts->ntransmitted;

	fprintf(stderr, "\r");
	fprintf(stderr, _("%ld/%ld packets, %d%% loss"), rts->nreceived, rts->ntransmitted, loss);

	if (rts->nreceived && rts->timing) {
		tavg = rts->tsum / (rts->nreceived + rts->nrepeats);

		fprintf(stderr, _(", min/avg/ewma/max = %ld.%03ld/%lu.%03ld/%d.%03d/%ld.%03ld ms"),
			(long)rts->tmin / 1000, (long)rts->tmin % 1000,
			tavg / 1000, tavg % 1000,
			rts->rtt / 8000, (rts->rtt / 8) % 1000, (long)rts->tmax / 1000, (long)rts->tmax % 1000);
	}
	fprintf(stderr, "\n");
}

inline int is_ours(struct ping_rts *rts, socket_st * sock, uint16_t id)
{
	return sock->socktype == SOCK_DGRAM || id == rts->ident;
}
