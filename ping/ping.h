#ifndef IPUTILS_PING_H
#define IPUTILS_PING_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/uio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <setjmp.h>
#include <asm/byteorder.h>
#include <sched.h>
#include <math.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <linux/filter.h>
#include <resolv.h>

#ifdef HAVE_LIBCAP
# include <sys/prctl.h>
# include <sys/capability.h>
#endif

#include "iputils_common.h"
#include "iputils_ni.h"

#ifdef USE_IDN
# define getaddrinfo_flags (AI_CANONNAME | AI_IDN | AI_CANONIDN)
# define getnameinfo_flags NI_IDN
#else
# define getaddrinfo_flags (AI_CANONNAME)
# define getnameinfo_flags 0
#endif

#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/errqueue.h>
#include <linux/in6.h>

#ifndef SCOPE_DELIMITER
# define SCOPE_DELIMITER '%'
#endif

#define	DEFDATALEN	(64 - 8)	/* default data length */

#define	MAXWAIT		10		/* max seconds to wait for response */
#define MIN_INTERVAL_MS	10		/* Minimal interpacket gap */
#define MIN_USER_INTERVAL_MS	2		/* Minimal allowed interval for non-root for single host ping */
#define MIN_MULTICAST_USER_INTERVAL_MS	1000	/* Minimal allowed interval for non-root for broadcast/multicast ping */
#define IDENTIFIER_MAX	0xFFFF		/* max unsigned 2-byte value */

#define SCHINT(a)	(((a) <= MIN_INTERVAL_MS) ? MIN_INTERVAL_MS : (a))


#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

/* RFC 4443 addition not yet available in libc headers */
#ifndef ICMP6_DST_UNREACH_POLICYFAIL
#define ICMP6_DST_UNREACH_POLICYFAIL 5
#endif

/* RFC 4443 addition not yet available in libc headers */
#ifndef ICMP6_DST_UNREACH_REJECTROUTE
#define ICMP6_DST_UNREACH_REJECTROUTE 6
#endif

/*
 * MAX_DUP_CHK is the number of bits in received table, i.e. the maximum
 * number of received sequence numbers we can keep track of.
 */
#define	MAX_DUP_CHK	0x10000

#if defined(__WORDSIZE) && __WORDSIZE == 64
# define USE_BITMAP64
#endif

#ifdef USE_BITMAP64
typedef uint64_t	bitmap_t;
# define BITMAP_SHIFT	6
#else
typedef uint32_t	bitmap_t;
# define BITMAP_SHIFT	5
#endif

#if ((MAX_DUP_CHK >> (BITMAP_SHIFT + 3)) << (BITMAP_SHIFT + 3)) != MAX_DUP_CHK
# error Please MAX_DUP_CHK and/or BITMAP_SHIFT
#endif

/* IPv4 packet size / IPv6 payload size */
#define	MAXPACKET	65535

struct rcvd_table {
	bitmap_t bitmap[MAX_DUP_CHK / (sizeof(bitmap_t) * 8)];
};

typedef struct socket_st {
	int fd;
	int socktype;
} socket_st;

struct ping_rts;

int ping4_run(struct ping_rts *rts, int argc, char **argv, struct addrinfo *ai, socket_st *sock);
int ping4_send_probe(struct ping_rts *rts, socket_st *, void *packet, unsigned packet_size);
int ping4_receive_error_msg(struct ping_rts *, socket_st *);
int ping4_parse_reply(struct ping_rts *, socket_st *, struct msghdr *msg, int cc, void *addr, struct timeval *);
void ping4_install_filter(struct ping_rts *rts, socket_st *);

typedef struct ping_func_set_st {
	int (*send_probe)(struct ping_rts *rts, socket_st *, void *packet, unsigned packet_size);
	int (*receive_error_msg)(struct ping_rts *rts, socket_st *sock);
	int (*parse_reply)(struct ping_rts *rts, socket_st *, struct msghdr *msg, int len, void *addr, struct timeval *);
	void (*install_filter)(struct ping_rts *rts, socket_st *);
} ping_func_set_st;

/* late include as dependent on ping_rts */
#include "ping_json.h"

/* Node Information query */
struct ping_ni {
	int query;
	int flag;
	void *subject;
	int subject_len;
	int subject_type;
	char *group;
#if PING6_NONCE_MEMORY
	uint8_t *nonce_ptr;
#else
	struct {
		struct timeval tv;
		pid_t pid;
	} nonce_secret;
#endif
};

/*ping runtime state */
struct ping_rts {
	unsigned int mark;
	unsigned char outpack[MAXPACKET];

	struct rcvd_table rcvd_tbl;

	int datalen;
	char *hostname;
	uid_t uid;
	int ident;			/* process id to identify our packets */

	int sndbuf;
	int ttl;

	long npackets;			/* max packets to transmit */
	long nreceived;			/* # of packets we got back */
	long nrepeats;			/* number of duplicates */
	long ntransmitted;		/* sequence # for outbound packets = #sent */
	long nchecksum;			/* replies with bad checksum */
	long nerrors;			/* icmp errors */
	int interval;			/* interval between packets (msec) */
	int preload;
	int deadline;			/* time to die */
	int lingertime;
	struct timespec start_time, cur_time;
	volatile int exiting;
	volatile int status_snapshot;
	int confirm;
	int confirm_flag;
	char *device;
	int pmtudisc;

	volatile int in_pr_addr;	/* pr_addr() is executing */
	jmp_buf pr_addr_jmp;

	/* timing */
	int timing;			/* flag to do timing */
	long tmin;			/* minimum round trip time */
	long tmax;			/* maximum round trip time */
	double tsum;			/* sum of all times, for doing average */
	double tsum2;
	int rtt;
	int rtt_addend;
	uint16_t acked;
	int pipesize;

	ping_func_set_st ping4_func_set;
	ping_func_set_st ping6_func_set;
	uint32_t tclass;
	uint32_t flowlabel;
	struct sockaddr_in6 source6;
	struct sockaddr_in6 whereto6;
	struct sockaddr_in6 firsthop6;
	int multicast;

	/* Used only in ping.c */
	int ts_type;
	int nroute;
	uint32_t route[10];
	struct sockaddr_in whereto;	/* who to ping */
	int optlen;
	int settos;			/* Set TOS, Precedence or other QOS options */
	int broadcast_pings;
	struct sockaddr_in source;

	/* Used only in ping_common.c */
	int screen_width;
#ifdef HAVE_LIBCAP
	cap_value_t cap_raw;
	cap_value_t cap_admin;
#endif

	/* Used only in ping6_common.c */
	int subnet_router_anycast; /* Subnet-Router anycast (RFC 4291) */
	struct sockaddr_in6 firsthop;
	unsigned char cmsgbuf[4096];
	size_t cmsglen;
	struct ping_ni ni;

	struct ping_json_buffer json_packet;
	struct ping_json_buffer json_stats;
	struct ping_json_buffer json_error;

	/* boolean option bits */
	unsigned int
		opt_adaptive:1,
		opt_audible:1,
		opt_connect_sk:1,
		opt_flood:1,
		opt_flood_poll:1,
		opt_flowinfo:1,
		opt_force_lookup:1,
		opt_interval:1,
		opt_latency:1,
		opt_mark:1,
		opt_noloop:1,
		opt_numeric:1,
		opt_outstanding:1,
		opt_pingfilled:1,
		opt_ptimeofday:1,
		opt_rtt_precision:1,
		opt_quiet:1,
		opt_json:1,
		opt_rroute:1,
		opt_so_debug:1,
		opt_so_dontroute:1,
		opt_sourceroute:1,
		opt_strictsource:1,
		opt_timestamp:1,
		opt_ttl:1,
		opt_verbose:1;
};
/* FIXME: global_rts will be removed in future */
extern struct ping_rts *global_rts;

#define	A(bit)	(rts->rcvd_tbl.bitmap[(bit) >> BITMAP_SHIFT])	/* identify word in array */
#define	B(bit)	(((bitmap_t)1) << ((bit) & ((1 << BITMAP_SHIFT) - 1)))	/* identify bit in word */

static inline void rcvd_set(struct ping_rts *rts, uint16_t seq)
{
	unsigned bit = seq % MAX_DUP_CHK;
	A(bit) |= B(bit);
}

static inline void rcvd_clear(struct ping_rts *rts, uint16_t seq)
{
	unsigned bit = seq % MAX_DUP_CHK;
	A(bit) &= ~B(bit);
}

static inline bitmap_t rcvd_test(struct ping_rts *rts, uint16_t seq)
{
	unsigned bit = seq % MAX_DUP_CHK;
	return A(bit) & B(bit);
}

/*
 * Write to stdout
 */
static inline void write_stdout(const char *str, size_t len)
{
	size_t o = 0;
	ssize_t cc;
	do {
		cc = write(STDOUT_FILENO, str + o, len - o);

		if (cc < 0)
			break;

		o += (size_t) cc;
	} while (len > o);
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

/*
 * tssub --
 *	Subtract 2 timespec structs:  out = out - in.  Out is assumed to
 * be >= in.
 */
static inline void tssub(struct timespec *out, struct timespec *in)
{
	if ((out->tv_nsec -= in->tv_nsec) < 0) {
		--out->tv_sec;
		out->tv_nsec += 1000000000;
	}
	out->tv_sec -= in->tv_sec;
}

static inline void set_signal(int signo, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
	sa.sa_flags = SA_RESTART;
	sigaction(signo, &sa, NULL);
}

extern int __schedule_exit(int next);

static inline int schedule_exit(struct ping_rts *rts, int next)
{
	if (rts->npackets && rts->ntransmitted >= rts->npackets && !rts->deadline)
		next = __schedule_exit(next);
	return next;
}

static inline int in_flight(struct ping_rts *rts)
{
	uint16_t diff = (uint16_t)rts->ntransmitted - rts->acked;
	return (diff <= 0x7FFF) ? diff : rts->ntransmitted - rts->nreceived - rts->nerrors;
}

static inline void acknowledge(struct ping_rts *rts, uint16_t seq)
{
	uint16_t diff = (uint16_t)rts->ntransmitted - seq;
	if (diff <= 0x7FFF) {
		if ((int)diff + 1 > rts->pipesize)
			rts->pipesize = (int)diff + 1;
		if ((int16_t)(seq - rts->acked) > 0 ||
		    (uint16_t)rts->ntransmitted - rts->acked > 0x7FFF)
			rts->acked = seq;
	}
}

static inline void advance_ntransmitted(struct ping_rts *rts)
{
	rts->ntransmitted++;
	/* Invalidate acked, if 16 bit seq overflows. */
	if ((uint16_t)rts->ntransmitted - rts->acked > 0x7FFF)
		rts->acked = (uint16_t)rts->ntransmitted + 1;
}

extern void usage(void) __attribute__((noreturn));
extern void limit_capabilities(struct ping_rts *rts);
static int enable_capability_raw(void);
static int disable_capability_raw(void);
static int enable_capability_admin(void);
static int disable_capability_admin(void);
#ifdef HAVE_LIBCAP
extern int modify_capability(cap_value_t, cap_flag_value_t);
static inline int enable_capability_raw(void)		{ return modify_capability(CAP_NET_RAW,   CAP_SET);   }
static inline int disable_capability_raw(void)		{ return modify_capability(CAP_NET_RAW,   CAP_CLEAR); }
static inline int enable_capability_admin(void)		{ return modify_capability(CAP_NET_ADMIN, CAP_SET);   }
static inline int disable_capability_admin(void)	{ return modify_capability(CAP_NET_ADMIN, CAP_CLEAR); }
#else
extern int modify_capability(int);
static inline int enable_capability_raw(void)		{ return modify_capability(1); }
static inline int disable_capability_raw(void)		{ return modify_capability(0); }
static inline int enable_capability_admin(void)		{ return modify_capability(1); }
static inline int disable_capability_admin(void)	{ return modify_capability(0); }
#endif
extern void drop_capabilities(void);

char *pr_addr(struct ping_rts *rts, void *sa, socklen_t salen);
char *pr_raw_addr(struct ping_rts *rts, void *sa, socklen_t salen);
char *str_interval(int interval);

int is_ours(struct ping_rts *rts, socket_st *sock, uint16_t id);
extern int pinger(struct ping_rts *rts, ping_func_set_st *fset, socket_st *sock);
extern void sock_setbufs(struct ping_rts *rts, socket_st *, int alloc);
extern void sock_setmark(struct ping_rts *rts, int fd);
extern void setup(struct ping_rts *rts, socket_st *);
extern int main_loop(struct ping_rts *rts, ping_func_set_st *fset, socket_st*,
		     uint8_t *packet, int packlen);
extern int finish(struct ping_rts *rts);
extern void status(struct ping_rts *rts);
extern void common_options(int ch);
extern int gather_statistics(struct ping_rts *rts, uint8_t *icmph, int icmplen,
			     int cc, uint16_t seq, int hops,
			     int csfailed, struct timeval *tv, char *from,
			     void (*pr_reply)(struct ping_rts *rts, uint8_t *ptr, int cc), int multicast,
			     int wrong_source);
extern void print_timestamp(struct ping_rts *rts);
void fill(struct ping_rts *rts, char *patp, unsigned char *packet, unsigned packet_size);

/* IPv6 */

int ping6_run(struct ping_rts *rts, int argc, char **argv, struct addrinfo *ai,
	      socket_st *sock);
void ping6_usage(unsigned from_ping);

int ping6_send_probe(struct ping_rts *rts, socket_st *sockets, void *packet, unsigned packet_size);
int ping6_receive_error_msg(struct ping_rts *rts, socket_st *sockets);
int ping6_parse_reply(struct ping_rts *rts, socket_st *, struct msghdr *msg, int cc, void *addr, struct timeval *);
void ping6_install_filter(struct ping_rts *rts, socket_st *sockets);
int ntohsp(uint16_t *p);

/* IPv6 node information query */

int niquery_is_enabled(struct ping_ni *ni);
void niquery_init_nonce(struct ping_ni *ni);
int niquery_option_handler(struct ping_ni *ni, const char *opt_arg);
int niquery_is_subject_valid(struct ping_ni *ni);
int niquery_check_nonce(struct ping_ni *ni, uint8_t *nonce);
void niquery_fill_nonce(struct ping_ni *ni, uint16_t seq, uint8_t *nonce);

#define NI_NONCE_SIZE			8

struct ni_hdr {
	struct icmp6_hdr		ni_u;
	uint8_t				ni_nonce[NI_NONCE_SIZE];
};

#define ni_type		ni_u.icmp6_type
#define ni_code		ni_u.icmp6_code
#define ni_cksum	ni_u.icmp6_cksum
#define ni_qtype	ni_u.icmp6_data16[0]
#define ni_flags	ni_u.icmp6_data16[1]

#endif /* IPUTILS_PING_H */
