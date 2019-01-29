/*-
 * Copyright (c) 1985, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 * Clockdiff computes the difference between the time of the machine on which it is
 * called and the time of the machines given as argument.  The time differences measured
 * by clockdiff are obtained using a sequence of ICMP TSTAMP messages which are returned
 * to the sender by the IP module in the remote machine.
 *
 * In order to compare clocks of machines in different time zones, the time is
 * transmitted (as a 32-bit value) in milliseconds since midnight UT.  If a hosts uses a
 * different time format, it should set the high order bit of the 32-bit quantity it
 * transmits.
 *
 * However, VMS apparently transmits the time in milliseconds since midnight local time
 * (rather than GMT) without setting the high order bit.  Furthermore, it does not
 * understand daylight-saving time.  This makes clockdiff behaving inconsistently with
 * hosts running VMS.
 *
 * In order to reduce the sensitivity to the variance of message transmission time,
 * clockdiff sends a sequence of messages.  Yet, measures between two `distant' hosts can
 * be affected by a small error.  The error can, however, be reduced by increasing the
 * number of messages sent in each measurement.
 */

#define TSPTYPES

#include <arpa/inet.h>
#include <errno.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#include "iputils_common.h"

enum {
	RANGE = 1,		/* best expected round-trip time, ms */
	MSGS = 50,
	TRIALS = 10,

	GOOD = 0,
	UNREACHABLE = 2,
	NONSTDTIME = 3,
	BREAK = 4,
	CONTINUE = 5,
	HOSTDOWN = 0x7fffffff,

	BIASP = 43199999,
	BIASN = -43200000,
	MODULO =  86400000,
	PROCESSING_TIME	= 0,	/* ms. to reduce error in measurement */

	PACKET_IN = 1024
};

struct run_state {
	int interactive;
	uint16_t id;
	int sock_raw;
	struct sockaddr_in server;
	int ip_opt_len;
	int measure_delta;
	int measure_delta1;
	unsigned short seqno;
	unsigned short seqno0;
	unsigned short acked;
	long rtt;
	long min_rtt;
	long rtt_sigma;
	char *hisname;
};

struct measure_vars {
	fd_set ready;
	struct timeval tv1;
	struct timeval tout;
	int count;
	int cc;
	unsigned char packet[PACKET_IN];
	socklen_t length;
	struct icmphdr *icp;
	struct iphdr *ip;
	int msgcount;
	long min1;
	long min2;
};

/*
 * All includes, definitions, struct declarations, and global variables are above.  After
 * this comment all you can find is functions.
 */

/*
 * addcarry() - checksum routine for Internet Protocol family headers.
 *
 * This routine is very heavily used in the network code and should be modified for each
 * CPU to be as fast as possible.
 *
 * This implementation is TAHOE version.
 */
static inline int addcarry(int sum)
{
	if (sum & 0xffff0000) {
		sum &= 0xffff;
		sum++;
	}
	return sum;
}

static int in_cksum(unsigned short *addr, int len)
{
	union word {
		char c[2];
		unsigned short s;
	} u;
	int sum = 0;

	while (len > 0) {
		/* add by words */
		while ((len -= 2) >= 0) {
			if ((unsigned long)addr & 0x1) {
				/* word is not aligned */
				u.c[0] = *(char *)addr;
				u.c[1] = *((char *)addr + 1);
				sum += u.s;
				addr++;
			} else
				sum += *addr++;
			sum = addcarry(sum);
		}
		if (len == -1)
			/* odd number of bytes */
			u.c[0] = *(unsigned char *)addr;
	}
	if (len == -1) {
		/*
		 * The last mbuf has odd # of bytes.  Follow the standard (the odd byte
		 * is shifted left by 8 bits)
		 */
		u.c[1] = 0;
		sum += u.s;
		sum = addcarry(sum);
	}
	return (~sum & 0xffff);
}

static int measure_inner_loop(struct run_state *ctl, struct measure_vars *mv)
{
	long delta1;
	long delta2;
	long diff;
	long histime = 0;
	long histime1 = 0;
	long recvtime;
	long sendtime;

	FD_ZERO(&mv->ready);
	FD_SET(ctl->sock_raw, &mv->ready);
	{
		long tmo = ctl->rtt + ctl->rtt_sigma;

		mv->tout.tv_sec = tmo / 1000;
		mv->tout.tv_usec = (tmo - (tmo / 1000) * 1000) * 1000;
	}

	if ((mv->count = select(FD_SETSIZE, &mv->ready, NULL, NULL, &mv->tout)) <= 0)
		return BREAK;

	gettimeofday(&mv->tv1, NULL);
	mv->cc = recvfrom(ctl->sock_raw, (char *)mv->packet, PACKET_IN, 0, NULL, &mv->length);

	if (mv->cc < 0)
		return (-1);

	mv->icp = (struct icmphdr *)(mv->packet + (mv->ip->ihl << 2));

	if (((ctl->ip_opt_len && mv->icp->type == ICMP_ECHOREPLY
	      && mv->packet[20] == IPOPT_TIMESTAMP)
	     || mv->icp->type == ICMP_TIMESTAMPREPLY)
	    && mv->icp->un.echo.id == ctl->id && mv->icp->un.echo.sequence >= ctl->seqno0
	    && mv->icp->un.echo.sequence <= ctl->seqno) {
		int i;
		uint8_t *opt = mv->packet + 20;

		if (ctl->acked < mv->icp->un.echo.sequence)
			ctl->acked = mv->icp->un.echo.sequence;
		if (ctl->ip_opt_len) {
			if ((opt[3] & 0xF) != IPOPT_TS_PRESPEC) {
				fprintf(stderr, _("Wrong timestamp %d\n"), opt[3] & 0xF);
				return NONSTDTIME;
			}
			if (opt[3] >> 4) {
				if ((opt[3] >> 4) != 1 || ctl->ip_opt_len != 4 + 3 * 8)
					fprintf(stderr, _("Overflow %d hops\n"), opt[3] >> 4);
			}
			sendtime = recvtime = histime = histime1 = 0;
			for (i = 0; i < (opt[2] - 5) / 8; i++) {
				uint32_t *timep = (uint32_t *) (opt + 4 + i * 8 + 4);
				uint32_t t = ntohl(*timep);

				if (t & 0x80000000)
					return NONSTDTIME;

				if (i == 0)
					sendtime = t;
				if (i == 1)
					histime = histime1 = t;
				if (i == 2) {
					if (ctl->ip_opt_len == 4 + 4 * 8)
						histime1 = t;
					else
						recvtime = t;
				}
				if (i == 3)
					recvtime = t;
			}

			if (!(sendtime & histime & histime1 & recvtime)) {
				fprintf(stderr, _("wrong timestamps\n"));
				return -1;
			}
		} else {
			recvtime = (mv->tv1.tv_sec % (24 * 60 * 60)) * 1000 +
					mv->tv1.tv_usec / 1000;
			sendtime = ntohl(*(uint32_t *) (mv->icp + 1));
		}
		diff = recvtime - sendtime;
		/* diff can be less than 0 around midnight */
		if (diff < 0)
			return CONTINUE;
		ctl->rtt = (ctl->rtt * 3 + diff) / 4;
		ctl->rtt_sigma = (ctl->rtt_sigma * 3 + labs(diff - ctl->rtt)) / 4;
		mv->msgcount++;
		if (!ctl->ip_opt_len) {
			histime = ntohl(((uint32_t *) (mv->icp + 1))[1]);
			/*
			 * a hosts using a time format different from ms.  since midnight
			 * UT (as per RFC792) should set the high order bit of the 32-bit
			 * time value it transmits.
			 */
			if ((histime & 0x80000000) != 0)
				return NONSTDTIME;
		}
		if (ctl->interactive) {
			printf(".");
			fflush(stdout);
		}

		delta1 = histime - sendtime;
		/*
		 * Handles wrap-around to avoid that around midnight small time
		 * differences appear enormous.  However, the two machine's clocks must
		 * be within 12 hours from each other.
		 */
		if (delta1 < BIASN)
			delta1 += MODULO;
		else if (delta1 > BIASP)
			delta1 -= MODULO;

		if (ctl->ip_opt_len)
			delta2 = recvtime - histime1;
		else
			delta2 = recvtime - histime;
		if (delta2 < BIASN)
			delta2 += MODULO;
		else if (delta2 > BIASP)
			delta2 -= MODULO;

		if (delta1 < mv->min1)
			mv->min1 = delta1;
		if (delta2 < mv->min2)
			mv->min2 = delta2;
		if (delta1 + delta2 < ctl->min_rtt) {
			ctl->min_rtt = delta1 + delta2;
			ctl->measure_delta1 = (delta1 - delta2) / 2 + PROCESSING_TIME;
		}
		if (diff < RANGE) {
			mv->min1 = delta1;
			mv->min2 = delta2;
			return BREAK;
		}
	}
	return CONTINUE;
}

/*
 * Measures the differences between machines' clocks using ICMP timestamp messages.
 */
static int measure(struct run_state *ctl)
{
	struct measure_vars mv = {
		.min1 = 0x7fffffff,
		.min2 = 0x7fffffff
	};
	unsigned char opacket[64] = { 0 };
	struct icmphdr *oicp = (struct icmphdr *)opacket;

	mv.ip = (struct iphdr *)mv.packet;
	ctl->min_rtt = 0x7fffffff;
	ctl->measure_delta = HOSTDOWN;
	ctl->measure_delta1 = HOSTDOWN;

	/* empties the icmp input queue */
	FD_ZERO(&mv.ready);
 empty:
	FD_SET(ctl->sock_raw, &mv.ready);
	if (select(FD_SETSIZE, &mv.ready, NULL, NULL, &mv.tout)) {
		mv.length = sizeof(struct sockaddr_in);
		mv.cc = recvfrom(ctl->sock_raw, (char *)mv.packet, PACKET_IN, 0,
			      NULL, &mv.length);
		if (mv.cc < 0)
			return -1;
		goto empty;
	}

	/*
	 * To measure the difference, select MSGS messages whose round-trip time is
	 * smaller than RANGE if ckrange is 1, otherwise simply select MSGS messages
	 * regardless of round-trip transmission time.  Choose the smallest transmission
	 * time in each of the two directions.  Use these two latter quantities to
	 * compute the delta between the two clocks.
	 */

	mv.length = sizeof(struct sockaddr_in);
	if (ctl->ip_opt_len)
		oicp->type = ICMP_ECHO;
	else
		oicp->type = ICMP_TIMESTAMP;
	oicp->code = 0;
	oicp->checksum = 0;
	oicp->un.echo.id = ctl->id;
	((uint32_t *) (oicp + 1))[0] = 0;
	((uint32_t *) (oicp + 1))[1] = 0;
	((uint32_t *) (oicp + 1))[2] = 0;
	FD_ZERO(&mv.ready);

	ctl->acked = ctl->seqno = ctl->seqno0 = 0;

	for (mv.msgcount = 0; mv.msgcount < MSGS;) {
		char escape = 0;

		/*
		 * If no answer is received for TRIALS consecutive times, the machine is
		 * assumed to be down
		 */
		if (ctl->seqno - ctl->acked > TRIALS) {
			errno = EHOSTDOWN;
			return HOSTDOWN;
		}

		oicp->un.echo.sequence = ++ctl->seqno;
		oicp->checksum = 0;

		gettimeofday(&mv.tv1, NULL);
		*(uint32_t *) (oicp + 1) =
		    htonl((mv.tv1.tv_sec % (24 * 60 * 60)) * 1000 + mv.tv1.tv_usec / 1000);
		oicp->checksum = in_cksum((unsigned short *)oicp, sizeof(*oicp) + 12);

		mv.count = sendto(ctl->sock_raw, (char *)opacket, sizeof(*oicp) + 12, 0,
			       (struct sockaddr *)&ctl->server, sizeof(struct sockaddr_in));

		if (mv.count < 0) {
			errno = EHOSTUNREACH;
			return UNREACHABLE;
		}

		while (!escape) {
			int ret = measure_inner_loop(ctl, &mv);

			switch (ret) {
				case BREAK:
					escape = 1;
					break;
				case CONTINUE:
					continue;
				default:
					return ret;
			}
		}
	}
	ctl->measure_delta = (mv.min1 - mv.min2) / 2 + PROCESSING_TIME;
	return GOOD;
}

static void usage(void)
{
	fprintf(stderr, _(
		"\nUsage:\n"
		"  clockdiff [options] <destination>\n"
		"\nOptions:\n"
		"                without -o, use ip timestamp only\n"
		"  -o            use ip timestamp and icmp echo\n"
		"  -o1           use three-term ip timestamp and icmp echo\n"
		"  -V            print version and exit\n"
		"  <destination> dns name or ip address\n"
		"\nFor more details see clockdiff(8).\n"));
	exit(1);
}

static void drop_rights(void)
{
#ifdef HAVE_LIBCAP
	cap_t caps = cap_init();

	if (cap_set_proc(caps))
		error(-1, errno, "cap_set_proc");
	cap_free(caps);
#endif
	if (setuid(getuid()))
		error(-1, errno, "setuid");
}

int main(int argc, char **argv)
{
	struct run_state ctl = {
		.rtt = 1000,
		0
	};
	int measure_status;

	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_flags = AI_CANONNAME
	};
	struct addrinfo *result;
	int status;

	atexit(close_stdout);
	if (argc == 2 && !strcmp(argv[1], "-V")) {
		printf(IPUTILS_VERSION("clockdiff"));
		return 0;
	}
	if (argc < 2) {
		drop_rights();
		usage();
	}

	ctl.sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (ctl.sock_raw < 0)
		error(1, errno, "socket");
	if (nice(-16) == -1)
		error(1, errno, "nice");
	drop_rights();

	if (argc == 3) {
		if (strcmp(argv[1], "-o") == 0) {
			ctl.ip_opt_len = 4 + 4 * 8;
			argv++;
		} else if (strcmp(argv[1], "-o1") == 0) {
			ctl.ip_opt_len = 4 + 3 * 8;
			argv++;
		} else
			usage();
	} else if (argc != 2)
		usage();

	if (isatty(fileno(stdin)) && isatty(fileno(stdout)))
		ctl.interactive = 1;

	ctl.id = getpid();

	status = getaddrinfo(argv[1], NULL, &hints, &result);
	if (status)
		error(1, 0, "%s: %s", argv[1], gai_strerror(status));
	ctl.hisname = strdup(result->ai_canonname);

	memcpy(&ctl.server, result->ai_addr, sizeof ctl.server);
	freeaddrinfo(result);

	if (connect(ctl.sock_raw, (struct sockaddr *)&ctl.server, sizeof(ctl.server)) == -1)
		error(1, errno, "connect");
	if (ctl.ip_opt_len) {
		struct sockaddr_in myaddr = { 0 };
		socklen_t addrlen = sizeof(myaddr);
		uint8_t *rspace;

		if ((rspace = calloc(ctl.ip_opt_len, sizeof(uint8_t))) == NULL)
			error(1, errno, "allocating %zu bytes failed",
					ctl.ip_opt_len * sizeof(uint8_t));
		rspace[0] = IPOPT_TIMESTAMP;
		rspace[1] = ctl.ip_opt_len;
		rspace[2] = 5;
		rspace[3] = IPOPT_TS_PRESPEC;
		if (getsockname(ctl.sock_raw, (struct sockaddr *)&myaddr, &addrlen) == -1)
			error(1, errno, "getsockname");
		((uint32_t *) (rspace + 4))[0 * 2] = myaddr.sin_addr.s_addr;
		((uint32_t *) (rspace + 4))[1 * 2] = ctl.server.sin_addr.s_addr;
		((uint32_t *) (rspace + 4))[2 * 2] = myaddr.sin_addr.s_addr;
		if (ctl.ip_opt_len == 4 + 4 * 8) {
			((uint32_t *) (rspace + 4))[2 * 2] = ctl.server.sin_addr.s_addr;
			((uint32_t *) (rspace + 4))[3 * 2] = myaddr.sin_addr.s_addr;
		}

		if (setsockopt(ctl.sock_raw, IPPROTO_IP, IP_OPTIONS, rspace, ctl.ip_opt_len) < 0) {
			error(0, errno, "IP_OPTIONS (fallback to icmp tstamps)");
			ctl.ip_opt_len = 0;
		}
		free(rspace);
	}

	measure_status = measure(&ctl);
	if (measure_status < 0) {
		if (errno)
			error(1, errno, "measure");
		error(1, 0, _("measure: unknown failure"));
	}

	switch (measure_status) {
	case HOSTDOWN:
		error(1, 0, _("%s is down"), ctl.hisname);
		break;
	case NONSTDTIME:
		error(1, 0, _("%s time transmitted in a non-standard format"), ctl.hisname);
		break;
	case UNREACHABLE:
		error(1, 0, _("%s is unreachable"), ctl.hisname);
		break;
	default:
		break;
	}

	{
		time_t now = time(NULL);

		if (ctl.interactive)
			printf(_("\nhost=%s rtt=%ld(%ld)ms/%ldms delta=%dms/%dms %s"),
				ctl.hisname, ctl.rtt, ctl.rtt_sigma, ctl.min_rtt,
				ctl.measure_delta, ctl.measure_delta1, ctime(&now));
		else
			printf("%ld %d %d\n", now, ctl.measure_delta, ctl.measure_delta1);
	}
	exit(0);
}
