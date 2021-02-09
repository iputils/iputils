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

/* 200 milliseconds => 20 Hz */
static const struct timespec MINUSERINTERVAL =
	{ .tv_sec = 0, .tv_nsec = 200 * MICROSECONDS_PER_SECOND };
/* 10 milliseconds => 100 Hz  */
static const struct timespec MININTERVAL =
	{ .tv_sec = 0, .tv_nsec = 10 * MICROSECONDS_PER_SECOND };

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

static int timespec_to_ms_int(struct timespec ts)
{
	return ts.tv_sec * 1000 + ts.tv_nsec / MICROSECONDS_PER_SECOND;
}

static double timespec_to_ms_double(struct timespec ts)
{
	return ts.tv_sec * 1000 + (ts.tv_nsec / (double)MICROSECONDS_PER_SECOND);
}

static char *timespec_to_ms_string(struct timespec ts, char *ret, size_t sz)
{
	double milliseconds;

	milliseconds = (ts.tv_sec * 1000) + (ts.tv_nsec / (double)MICROSECONDS_PER_SECOND);
	if (milliseconds < 1)
		snprintf(ret, sz, "%0.03f", milliseconds);
	else if (milliseconds < 10)
		snprintf(ret, sz, "%0.02f", milliseconds);
	else if (milliseconds < 100)
		snprintf(ret, sz, "%0.01f", milliseconds);
	else
		snprintf(ret, sz, "%.0f", milliseconds);
	return ret;
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
		size_t max = packet_size < (size_t)(8 + ii) ? 0 : packet_size - (8 + ii);

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
	static struct timespec waittime = { .tv_sec = 0, .tv_nsec = 0 };
	static struct timespec next_time;
	struct itimerval it;

	if (waittime.tv_sec != 0 || waittime.tv_nsec != 0)
		return next;

	if (global_rts->nreceived) {
		timespecadd(&global_rts->tmax, &global_rts->tmax, &waittime);
		if (timespeccmp(&waittime, &global_rts->interval) < 0)
			waittime = global_rts->interval;
	} else
		waittime = global_rts->lingertime;

	next_time.tv_sec = next / 1000;
	next_time.tv_nsec = (next % 1000) * MICROSECONDS_PER_SECOND;
	if (next < 0 || timespeccmp(&next_time, &waittime) < 0)
		next = (int) waittime.tv_sec;

	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	TIMESPEC_TO_TIMEVAL(&it.it_value, &waittime);
	setitimer(ITIMER_REAL, &it, NULL);
	return next;
}

static void ewma_update(struct ewma *avg, struct timespec update)
{
	if (avg->ts.tv_sec || avg->ts.tv_nsec) {
		struct timespec a, b, c;

		a = timespecmultiply(&avg->ts, avg->weight - 1);
		b = timespecmultiply(&update, avg->factor);
		timespecadd(&a, &b, &c);
		avg->ts = timespecdivide(&c, avg->weight);
	} else {
		/* Should happen only first call to ewma_update() */
		avg->ts = update;
		avg->weight = 8;
		avg->factor = 1;
	}
}

static void update_interval(struct ping_rts *rts)
{
	struct timespec est;

	if (rts->ewma.ts.tv_sec != 0 || rts->ewma.ts.tv_nsec != 0)
		est = timespecdivide(&rts->ewma.ts, 8);
	else
		est = rts->interval;
	timespecadd(&est, &rts->frequency_change, &rts->interval);
	if (rts->uid == 0) {
		if (timespeccmp(&rts->interval, &MININTERVAL) < 0)
			rts->interval = MININTERVAL;
	} else {
		if (timespeccmp(&rts->interval, &MINUSERINTERVAL) < 0)
			rts->interval = MINUSERINTERVAL;
	}
}

/*
 * Print timestamp
 */
void print_timestamp(char const *const open, struct ping_rts const *const rts,
		     char const *const close)
{
	if (rts->opt_ptimeofday) {
		struct timespec ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		printf("%s%lu.%06lu%s ", open, ts.tv_sec, ts.tv_nsec / 1000, close);
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
		clock_gettime(CLOCK_REALTIME, &rts->cur_time);
		tokens = (timespec_to_ms_int(rts->interval) * (rts->preload - 1)) / 1000;
	} else {
		int ntokens, tmp;
		struct timespec ts, diff;

		clock_gettime(CLOCK_REALTIME, &ts);
		timespecsub(&ts, &rts->cur_time, &diff);
		ntokens = timespec_to_ms_int(diff);
		if (!rts->interval.tv_sec && !rts->interval.tv_nsec) {
			/* Case of unlimited flood is special;
			 * if we see no reply, they are limited to 100pps */
			if (ntokens < timespec_to_ms_int(MININTERVAL) &&
			    in_flight(rts) >= rts->preload)
				return timespec_to_ms_int(MININTERVAL) - ntokens;
		}
		ntokens += tokens;
		tmp = (timespec_to_ms_int(rts->interval) * rts->preload);
		if (tmp < ntokens)
			ntokens = tmp;
		if (ntokens < timespec_to_ms_int(rts->interval))
			return timespec_to_ms_int(rts->interval) - ntokens;

		rts->cur_time = ts;
		tokens = ntokens - timespec_to_ms_int(rts->interval);
	}

	if (rts->opt_outstanding) {
		if (rts->ntransmitted > 0 && !rcvd_test(rts, rts->ntransmitted)) {
			print_timestamp("[", rts, "]");
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
		return timespec_to_ms_int(rts->interval) - tokens;
	}

	/* And handle various errors... */
	if (i > 0) {
		/* Apparently, it is some fatal bug. */
		abort();
	} else if (errno == ENOBUFS || errno == ENOMEM) {
		struct timespec nores_interval, addition;
		/* nores_min == 0.5 seconds */
		struct timespec const nores_min = {
			.tv_sec = 0,
			.tv_nsec = 500 * MICROSECONDS_PER_SECOND
		};

		/* Device queue overflow or OOM. Packet is not sent. */
		tokens = 0;
		/* Slowdown. This works only in adaptive mode (option -A) */
		addition = timespecmultiply(&rts->ewma.ts, 8);
		timespecadd(&rts->frequency_change, &addition, &rts->frequency_change);
		if (rts->opt_adaptive)
			update_interval(rts);
		nores_interval = timespecdivide(&rts->interval, 2);
		if (timespeccmp(&nores_interval, &nores_min) < 0)
			nores_interval = nores_min;
		oom_count++;
		if (oom_count * timespeccmp(&nores_interval, &rts->lingertime) < 1)
			return timespec_to_ms_int(nores_interval);
		i = 0;
		/* Fall to hard error. It is to avoid complete deadlock
		 * on stuck output device even when dealine was not requested.
		 * Expected timings are screwed up in any case, but we will
		 * exit some day. :-) */
	} else if (errno == EAGAIN) {
		/* Socket buffer is full. */
		tokens += timespec_to_ms_int(rts->interval);
		return timespec_to_ms_int(MININTERVAL);
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
	if (timespeccmp(&rts->interval, &MININTERVAL) < 0)
		return timespec_to_ms_int(MININTERVAL);
	return timespec_to_ms_int(rts->interval);
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
	struct timespec ts;
	struct timeval tv;
	sigset_t sset;

	if (rts->opt_flood && !rts->opt_interval)
		memset(&rts->interval, 0, sizeof(rts->interval));

	if (rts->uid && timespeccmp(&rts->interval, &MINUSERINTERVAL) < 0)
		error(2, 0, _("cannot flood; minimal interval allowed for user is %dms"),
			    timespec_to_ms_int(MINUSERINTERVAL));

	if ((INT_MAX / rts->preload) <= timespec_to_ms_int(rts->interval))
		error(2, 0, _("illegal preload (%d) and/or interval (%ld.%09ld)"),
			    rts->preload, rts->interval.tv_sec, rts->interval.tv_nsec);

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
	ts.tv_sec = 1;
	ts.tv_nsec = 0;
	if (timespeccmp(&ts, &rts->interval) < 0)
		ts = rts->interval;
	TIMESPEC_TO_TIMEVAL(&tv, &ts);
	/* FIXME: replace SO_SNDTIMEO with ppoll() */
	setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));

	/* Set RCVTIMEO to "interval". Note, it is just an optimization
	 * allowing to avoid redundant poll(). */
	ts.tv_sec = rts->interval.tv_sec;
	ts.tv_nsec = rts->interval.tv_nsec;
	TIMESPEC_TO_TIMEVAL(&tv, &ts);
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

	clock_gettime(CLOCK_REALTIME, &rts->start_time);

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
	cp = ((u_char *)ptr) + sizeof(struct timespec);
	dp = &rts->outpack[8 + sizeof(struct timespec)];
	for (i = sizeof(struct timespec); i < rts->datalen; ++i, ++cp, ++dp) {
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

		/* FIXME: everyone has new enough kernel, rewrite the whole thing. */
		/* Technical part. Looks wicked. Could be dropped,
		 * if everyone used the newest kernel. :-)
		 * Its purpose is:
		 * 1. Provide intervals less than resolution of scheduler.
		 *    Solution: spinning.
		 * 2. Avoid use of poll(), when recvmsg() can provide
		 *    timed waiting (SO_RCVTIMEO). */
		polling = 0;
		recv_error = 0;
		if (rts->opt_adaptive || rts->opt_flood_poll ||
		    next < timespec_to_ms_int(SCHINT(rts->interval))) {
			int recv_expected = in_flight(rts);

			/* If we are here, recvmsg() is unable to wait for
			 * required timeout. */
			if (1000 % HZ == 0 ? next <= 1000 / HZ : (next < INT_MAX / HZ && next * HZ <= 1000)) {
				/* Very short timeout... So, if we wait for
				 * something, we sleep for MININTERVAL.
				 * Otherwise, spin! */
				if (recv_expected) {
					next = timespec_to_ms_int(MININTERVAL);
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
			    (rts->opt_adaptive || rts->opt_flood_poll ||
			     rts->interval.tv_sec || rts->interval.tv_nsec)) {
				struct pollfd pset;

				pset.fd = sock->fd;
				pset.events = POLLIN;
				pset.revents = 0;
				/* FIXME: use ppoll()  */
				if (poll(&pset, 1, next) < 1 ||
				    !(pset.revents & (POLLIN | POLLERR)))
					continue;
				polling = MSG_DONTWAIT;
				recv_error = pset.revents & POLLERR;
			}
		}

		for (;;) {
			struct timespec recv_time;
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
					struct timeval *tv;

					if (c->cmsg_level != SOL_SOCKET ||
					    c->cmsg_type != SO_TIMESTAMP)
						continue;
					if (c->cmsg_len < CMSG_LEN(sizeof(struct timespec)))
						continue;
					/* SO_TIMESTAMP is timeval, see: man 7 socket */
					tv = (struct timeval *)CMSG_DATA(c);
					TIMEVAL_TO_TIMESPEC(tv, &recv_time);
				}
#endif

				if (rts->opt_latency ||
				    (recv_time.tv_sec == 0 && recv_time.tv_nsec == 0)) {
					if (rts->opt_latency ||
					    ioctl(sock->fd, SIOCGSTAMP, &recv_time)) {
						clock_gettime(CLOCK_REALTIME, &recv_time);
					}
				}

				not_ours = fset->parse_reply(rts, sock, &msg, cc, addrbuf, &recv_time);
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
		      int csfailed, struct timespec *ts, char *from,
		      void (*pr_reply)(uint8_t *icmph, int cc), int multicast)
{
	int dupflag = 0;
	struct timespec time_diff;
	uint8_t *ptr = icmph + icmplen;

	++rts->nreceived;
	if (!csfailed)
		acknowledge(rts, seq);

	if (rts->timing && cc >= (int)(8 + sizeof(struct timespec))) {
		struct timespec recv_timestamp;
		memcpy(&recv_timestamp, ptr, sizeof(recv_timestamp));

restamp:
		timespecsub(ts, &recv_timestamp, &time_diff);
		if (time_diff.tv_sec < 0 || (time_diff.tv_sec == 0 && time_diff.tv_nsec < 0)) {
			error(0, 0, _("Warning: time of day goes back (-%ld.%09ld), taking countermeasures"),
			      labs(time_diff.tv_sec), labs(time_diff.tv_nsec));
			if (!rts->opt_latency) {
				clock_gettime(CLOCK_REALTIME, ts);
				rts->opt_latency = 1;
				goto restamp;
			}
		}
		if (!csfailed) {
			double t;

			timespecadd(&rts->tsum, &time_diff, &rts->tsum);
			t = timespec_to_ms_double(time_diff);
			rts->tsum2 += t * t;
			if (timespeccmp(&time_diff, &rts->tmin) < 0)
				rts->tmin = time_diff;
			if (timespeccmp(&rts->tmax, &time_diff) < 0)
				rts->tmax = time_diff;
			ewma_update(&rts->ewma, time_diff);
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

		print_timestamp("[", rts, "]");
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
			char s[32];
			printf(" time=%s ms", timespec_to_ms_string(time_diff, s, sizeof(s)));
		}
		if (dupflag && (!multicast || rts->opt_verbose))
			printf(_(" (DUP!)"));
		if (csfailed)
			printf(_(" (BAD CHECKSUM!)"));

		/* check the data */
		cp = ((unsigned char *)ptr) + sizeof(struct timespec);
		dp = &rts->outpack[8 + sizeof(struct timespec)];
		for (i = sizeof(struct timespec); i < rts->datalen; ++i, ++cp, ++dp) {
			if (*cp != *dp) {
				printf(_("\nwrong data byte #%zu should be 0x%x but was 0x%x"),
				       i, *dp, *cp);
				cp = (unsigned char *)ptr + sizeof(struct timespec);
				for (i = sizeof(struct timespec); i < rts->datalen; ++i, ++cp) {
					if ((i % 32) == sizeof(struct timespec))
						printf("\n#%zu\t", i);
					printf("%x ", *cp);
				}
				break;
			}
		}
	}
	return 0;
}

/*
 * finish --
 *	Print out statistics, and give up.
 */
int finish(struct ping_rts *rts)
{
	struct timespec ts;
	char *comma = "";

	timespecsub(&rts->cur_time, &rts->start_time, &ts);

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
		printf(_(", %g%% packet loss"),
			  ((rts->ntransmitted - rts->nreceived) * (double)100.0) /
			  (double)rts->ntransmitted);
		printf(_(", time %.0fms"), timespec_to_ms_double(ts));
	}

	putchar('\n');

	if (rts->nreceived && rts->timing) {
		struct timespec average;
		double std_deviation;
		const long total = rts->nreceived + rts->nrepeats;

		average = timespecdivide(&rts->tsum, total);
		{
			double avg;
			double variance;

			avg = timespec_to_ms_double(average);
			variance = (rts->tsum2 / total) - (avg * avg);
			std_deviation = sqrt(variance);
		}
		printf(_("rtt min/avg/max/mdev = %0.03f/%0.03f/%0.03f/%0.03f ms"),
		       timespec_to_ms_double(rts->tmin),
		       timespec_to_ms_double(average),
		       timespec_to_ms_double(rts->tmax),
		       std_deviation);
		comma = ", ";
	}
	if (rts->pipesize > 1) {
		printf(_("%spipe %d"), comma, rts->pipesize);
		comma = ", ";
	}

	if (rts->nreceived && (rts->opt_flood || rts->opt_adaptive)
	    && rts->ntransmitted > 1) {
		struct timespec ipg;

		ipg = timespecdivide(&ts, rts->ntransmitted - 1);
		printf(_("%sipg/ewma %0.03f/%0.3f ms"), comma,
		       timespec_to_ms_double(ipg),
		       timespec_to_ms_double(rts->ewma.ts));
	}
	putchar('\n');
	return (!rts->nreceived || (rts->deadline && rts->nreceived < rts->npackets));
}

void status(struct ping_rts *rts)
{
	int loss = 0;

	rts->status_snapshot = 0;

	if (rts->ntransmitted)
		loss = (((long long)(rts->ntransmitted - rts->nreceived)) * 100) / rts->ntransmitted;

	fprintf(stderr, "\r");
	fprintf(stderr, _("%ld/%ld packets, %d%% loss"), rts->nreceived, rts->ntransmitted, loss);

	if (rts->nreceived && rts->timing) {
		struct timespec average;

		average = timespecdivide(&rts->tsum, rts->nreceived + rts->nrepeats);
		fprintf(stderr, _(", min/avg/ewma/max = %ld.%09ld/%lu.%09ld/%ld.%09ld/%ld.%09ld s"),
			rts->tmin.tv_sec, rts->tmin.tv_nsec,
			average.tv_sec, average.tv_nsec,
			rts->ewma.ts.tv_sec, rts->ewma.ts.tv_nsec,
			rts->tmax.tv_sec, rts->tmax.tv_nsec);
	}
	fprintf(stderr, "\n");
}

inline int is_ours(struct ping_rts *rts, socket_st * sock, uint16_t id)
{
	return sock->socktype == SOCK_DGRAM || id == rts->ident;
}
