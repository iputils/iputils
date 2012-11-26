#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <setjmp.h>

#ifdef CAPABILITIES
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#ifdef USE_IDN
#include <locale.h>
#include <idna.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/errqueue.h>

#include "SNAPSHOT.h"

#define	DEFDATALEN	(64 - 8)	/* default data length */

#define	MAXWAIT		10		/* max seconds to wait for response */
#define MININTERVAL	10		/* Minimal interpacket gap */
#define MINUSERINTERVAL	200		/* Minimal allowed interval for non-root */

#define SCHINT(a)	(((a) <= MININTERVAL) ? MININTERVAL : (a))

/* various options */
extern int options;
#define	F_FLOOD		0x001
#define	F_INTERVAL	0x002
#define	F_NUMERIC	0x004
#define	F_PINGFILLED	0x008
#define	F_QUIET		0x010
#define	F_RROUTE	0x020
#define	F_SO_DEBUG	0x040
#define	F_SO_DONTROUTE	0x080
#define	F_VERBOSE	0x100
#define	F_TIMESTAMP	0x200
#define	F_FLOWINFO	0x200
#define	F_SOURCEROUTE	0x400
#define	F_TCLASS	0x400
#define	F_FLOOD_POLL	0x800
#define	F_LATENCY	0x1000
#define	F_AUDIBLE	0x2000
#define	F_ADAPTIVE	0x4000
#define	F_STRICTSOURCE	0x8000
#define F_NOLOOP	0x10000
#define F_TTL		0x20000
#define F_MARK		0x40000
#define F_PTIMEOFDAY	0x80000
#define F_OUTSTANDING	0x100000

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.
 */
#define	MAX_DUP_CHK	0x10000

#if defined(__WORDSIZE) && __WORDSIZE == 64
# define USE_BITMAP64
#endif

#ifdef USE_BITMAP64
typedef __u64	bitmap_t;
# define BITMAP_SHIFT	6
#else
typedef __u32	bitmap_t;
# define BITMAP_SHIFT	5
#endif

#if ((MAX_DUP_CHK >> (BITMAP_SHIFT + 3)) << (BITMAP_SHIFT + 3)) != MAX_DUP_CHK
# error Please MAX_DUP_CHK and/or BITMAP_SHIFT
#endif

struct rcvd_table {
	bitmap_t bitmap[MAX_DUP_CHK / (sizeof(bitmap_t) * 8)];
};

extern struct rcvd_table rcvd_tbl;

#define	A(bit)	(rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT])	/* identify word in array */
#define	B(bit)	(((bitmap_t)1) << ((bit) & ((1 << BITMAP_SHIFT) - 1)))	/* identify bit in word */

static inline void rcvd_set(__u16 seq)
{
	unsigned bit = seq % MAX_DUP_CHK;
	A(bit) |= B(bit);
}

static inline void rcvd_clear(__u16 seq)
{
	unsigned bit = seq % MAX_DUP_CHK;
	A(bit) &= ~B(bit);
}

static inline bitmap_t rcvd_test(__u16 seq)
{
	unsigned bit = seq % MAX_DUP_CHK;
	return A(bit) & B(bit);
}

extern u_char outpack[];
extern int maxpacket;

extern int datalen;
extern char *hostname;
extern int uid;
extern int ident;			/* process id to identify our packets */

extern int sndbuf;
extern int ttl;

extern long npackets;			/* max packets to transmit */
extern long nreceived;			/* # of packets we got back */
extern long nrepeats;			/* number of duplicates */
extern long ntransmitted;		/* sequence # for outbound packets = #sent */
extern long nchecksum;			/* replies with bad checksum */
extern long nerrors;			/* icmp errors */
extern int interval;			/* interval between packets (msec) */
extern int preload;
extern int deadline;			/* time to die */
extern int lingertime;
extern struct timeval start_time, cur_time;
extern volatile int exiting;
extern volatile int status_snapshot;
extern int confirm;
extern int confirm_flag;
extern int working_recverr;

extern volatile int in_pr_addr;		/* pr_addr() is executing */
extern jmp_buf pr_addr_jmp;

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif


/* timing */
extern int timing;			/* flag to do timing */
extern long tmin;			/* minimum round trip time */
extern long tmax;			/* maximum round trip time */
extern long long tsum;			/* sum of all times, for doing average */
extern long long tsum2;
extern int rtt;
extern __u16 acked;
extern int pipesize;

#define COMMON_OPTIONS \
case 'a': case 'U': case 'c': case 'd': \
case 'f': case 'i': case 'w': case 'l': \
case 'S': case 'n': case 'p': case 'q': \
case 'r': case 's': case 'v': case 'L': \
case 't': case 'A': case 'W': case 'B': case 'm': \
case 'D': case 'O':

#define COMMON_OPTSTR "h?VQ:I:M:aUc:dfi:w:l:S:np:qrs:vLt:AW:Bm:DO"

/*
 * Write to stdout
 */
static inline void write_stdout(const char *str, size_t len)
{
	size_t o = 0;
	ssize_t cc;
	do {
		cc = write(STDOUT_FILENO, str + o, len - o);
		o += cc;
	} while (len > o || cc < 0);
}

/*
 * tvsub --
 *	Subtract 2 timeval structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static inline void tvsub(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static inline void set_signal(int signo, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
#ifdef SA_INTERRUPT
	sa.sa_flags = SA_INTERRUPT;
#endif
	sigaction(signo, &sa, NULL);
}

extern int __schedule_exit(int next);

static inline int schedule_exit(int next)
{
	if (npackets && ntransmitted >= npackets && !deadline)
		next = __schedule_exit(next);
	return next;
}

static inline int in_flight(void)
{
	__u16 diff = (__u16)ntransmitted - acked;
	return (diff<=0x7FFF) ? diff : ntransmitted-nreceived-nerrors;
}

static inline void acknowledge(__u16 seq)
{
	__u16 diff = (__u16)ntransmitted - seq;
	if (diff <= 0x7FFF) {
		if ((int)diff+1 > pipesize)
			pipesize = (int)diff+1;
		if ((__s16)(seq - acked) > 0 ||
		    (__u16)ntransmitted - acked > 0x7FFF)
			acked = seq;
	}
}

static inline void advance_ntransmitted(void)
{
	ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows. */
	if ((__u16)ntransmitted - acked > 0x7FFF)
		acked = (__u16)ntransmitted + 1;
}

extern void limit_capabilities(void);
static int enable_capability_raw(void);
static int disable_capability_raw(void);
static int enable_capability_admin(void);
static int disable_capability_admin(void);
#ifdef CAPABILITIES
extern int modify_capability(cap_value_t, cap_flag_value_t);
static inline int enable_capability_raw(void)		{ return modify_capability(CAP_NET_RAW,   CAP_SET);   };
static inline int disable_capability_raw(void)		{ return modify_capability(CAP_NET_RAW,   CAP_CLEAR); };
static inline int enable_capability_admin(void)		{ return modify_capability(CAP_NET_ADMIN, CAP_SET);   };
static inline int disable_capability_admin(void)	{ return modify_capability(CAP_NET_ADMIN, CAP_CLEAR); };
#else
extern int modify_capability(int);
static inline int enable_capability_raw(void)		{ return modify_capability(1); };
static inline int disable_capability_raw(void)		{ return modify_capability(0); };
static inline int enable_capability_admin(void)		{ return modify_capability(1); };
static inline int disable_capability_admin(void)	{ return modify_capability(0); };
#endif
extern void drop_capabilities(void);

extern int send_probe(void);
extern int receive_error_msg(void);
extern int parse_reply(struct msghdr *msg, int len, void *addr, struct timeval *);
extern void install_filter(void);

extern int pinger(void);
extern void sock_setbufs(int icmp_sock, int alloc);
extern void setup(int icmp_sock);
extern void main_loop(int icmp_sock, __u8 *buf, int buflen) __attribute__((noreturn));
extern void finish(void) __attribute__((noreturn));
extern void status(void);
extern void common_options(int ch);
extern int gather_statistics(__u8 *ptr, int icmplen,
			     int cc, __u16 seq, int hops,
			     int csfailed, struct timeval *tv, char *from,
			     void (*pr_reply)(__u8 *ptr, int cc));
extern void print_timestamp(void);
