/*
 * arping.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * 		YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#ifdef HAVE_LIBCAP
#include <sys/prctl.h>
#include <sys/capability.h>
#endif

#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef USE_SYSFS
#include <sys/types.h>
#include <dirent.h>
#endif

#include <ifaddrs.h>

#ifdef USE_IDN
#include <locale.h>

#ifndef AI_IDN
#define AI_IDN 0x0040
#endif
#ifndef AI_CANONIDN
#define AI_CANONIDN 0x0080
#endif
#endif

#ifdef DEFAULT_DEVICE
# define DEFAULT_DEVICE_STR	DEFAULT_DEVICE
#else
# define DEFAULT_DEVICE		NULL
#endif

struct device {
	char *name;
	int ifindex;
	struct ifaddrs *ifa;
#ifdef USE_SYSFS
	struct sysfs_devattr_values *sysfs;
#endif
};

struct run_state {
	struct device device;
	char *source;
	struct in_addr gsrc;
	struct in_addr gdst;
	char *target;
	int count;
	int timeout;
	unsigned int interval;
	int socketfd;
	struct sockaddr_storage me;
	struct sockaddr_storage he;
	struct timespec start;
	struct timespec last;
	int sent;
	int brd_sent;
	int received;
	int brd_recv;
	int req_recv;
#ifndef HAVE_LIBCAP
	uid_t euid;
#endif
	unsigned int
		advert:1,
		broadcast_only:1,
		dad:1,
		quiet:1,
		quit_on_reply:1,
		unicasting:1,
		unsolicited:1;
};
struct run_state *global_ptr;

#define MS_TDIFF(tv1,tv2) ( ((tv1).tv_sec-(tv2).tv_sec)*1000 + \
			   ((tv1).tv_usec-(tv2).tv_usec)/1000 )

__attribute__((const)) static inline size_t sll_len(const size_t halen)
{
	const struct sockaddr_ll unused;
	const size_t len = sizeof(unused.sll_addr) + halen;

	if (len < sizeof(unused))
		return sizeof(unused);
	return len;
}

void usage(void)
{
	fprintf(stderr,
		"\nUsage:\n"
		"  arping [options] <destination>\n"
		"\nOptions:\n"
		"  -f            quit on first reply\n"
		"  -q            be quiet\n"
		"  -b            keep on broadcasting, do not unicast\n"
		"  -D            duplicate address detection mode\n"
		"  -U            unsolicited ARP mode, update your neighbours\n"
		"  -A            ARP answer mode, update your neighbours\n"
		"  -V            print version and exit\n"
		"  -c <count>    how many packets to send\n"
		"  -w <timeout>  how long to wait for a reply\n"
		"  -i <interval> set interval between packets (default: 1 second)\n"
		"  -I <device>   which ethernet device to use"
#ifdef DEFAULT_DEVICE_STR
				"(" DEFAULT_DEVICE_STR ")"
#endif
				"\n"
		"  -s <source>   source ip address\n"
		"  <destination> dns name or ip address\n"
		"\nFor more details see arping(8).\n"
	);
	exit(2);
}

void set_signal(int signo, void (*handler)(void))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = (void (*)(int))handler;
	sa.sa_flags = SA_RESTART;
	sigaction(signo, &sa, NULL);
}

#ifdef HAVE_LIBCAP
static const cap_value_t caps[] = { CAP_NET_RAW, };
static cap_flag_value_t cap_raw = CAP_CLEAR;
#endif

#ifdef HAVE_LIBCAP
void limit_capabilities(void)
{
	cap_t cap_p;

	cap_p = cap_get_proc();
	if (!cap_p) {
		perror("arping: cap_get_proc");
		exit(-1);
	}

	cap_get_flag(cap_p, CAP_NET_RAW, CAP_PERMITTED, &cap_raw);

	if (cap_raw != CAP_CLEAR) {
		if (cap_clear(cap_p) < 0) {
			perror("arping: cap_clear");
			exit(-1);
		}

		cap_set_flag(cap_p, CAP_PERMITTED, 1, caps, CAP_SET);

		if (cap_set_proc(cap_p) < 0) {
			perror("arping: cap_set_proc");
			if (errno != EPERM)
				exit(-1);
		}
	}

	if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
		perror("arping: prctl");
		exit(-1);
	}

	if (setuid(getuid()) < 0) {
		perror("arping: setuid");
		exit(-1);
	}

	if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
		perror("arping: prctl");
		exit(-1);
	}

	cap_free(cap_p);
}
#else
void limit_capabilities(struct run_state *ctl)
{
	ctl->euid = geteuid();
}
#endif

#ifdef HAVE_LIBCAP
int modify_capability_raw(struct run_state *ctl __attribute__((__unused__)), int on)
{
	cap_t cap_p;

	if (cap_raw != CAP_SET)
		return on ? -1 : 0;

	cap_p = cap_get_proc();
	if (!cap_p) {
		perror("arping: cap_get_proc");
		return -1;
	}

	cap_set_flag(cap_p, CAP_EFFECTIVE, 1, caps, on ? CAP_SET : CAP_CLEAR);

	if (cap_set_proc(cap_p) < 0) {
		perror("arping: cap_set_proc");
		return -1;
	}

	cap_free(cap_p);
	return 0;
}
#else
int modify_capability_raw(struct run_state *ctl, int on)
{
	if (setuid(on ? ctl->euid : getuid())) {
		perror("arping: setuid");
		return -1;
	}
	return 0;
}
#endif

static inline int enable_capability_raw(struct run_state *ctl)
{
	return modify_capability_raw(ctl, 1);
}

static inline int disable_capability_raw(struct run_state *ctl)
{
	return modify_capability_raw(ctl, 0);
}

void drop_capabilities(void)
{
#ifdef HAVE_LIBCAP
	cap_t cap_p = cap_init();

	if (!cap_p) {
		perror("arping: cap_init");
		exit(-1);
	}

	if (cap_set_proc(cap_p) < 0) {
		perror("arping: cap_set_proc");
		exit(-1);
	}

	cap_free(cap_p);
#else
	if (setuid(getuid()) < 0) {
		perror("arping: setuid");
		exit(-1);
	}
#endif
}

int send_pack(struct run_state *ctl)
{
	int err;
	struct timespec now;
	unsigned char buf[256];
	struct arphdr *ah = (struct arphdr*)buf;
	unsigned char *p = (unsigned char *)(ah+1);
	struct sockaddr_ll *ME = (struct sockaddr_ll *)&(ctl->me);
	struct sockaddr_ll *HE = (struct sockaddr_ll *)&(ctl->he);

	ah->ar_hrd = htons(ME->sll_hatype);
	if (ah->ar_hrd == htons(ARPHRD_FDDI))
		ah->ar_hrd = htons(ARPHRD_ETHER);
	ah->ar_pro = htons(ETH_P_IP);
	ah->ar_hln = ME->sll_halen;
	ah->ar_pln = 4;
	ah->ar_op  = ctl->advert ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

	memcpy(p, &ME->sll_addr, ah->ar_hln);
	p+=ME->sll_halen;

	memcpy(p, &ctl->gsrc, 4);
	p+=4;

	if (ctl->advert)
		memcpy(p, &ME->sll_addr, ah->ar_hln);
	else
		memcpy(p, &HE->sll_addr, ah->ar_hln);
	p+=ah->ar_hln;

	memcpy(p, &ctl->gdst, 4);
	p+=4;

	clock_gettime(CLOCK_MONOTONIC, &now);
	err = sendto(ctl->socketfd, buf, p-buf, 0, (struct sockaddr*)HE, sll_len(ah->ar_hln));
	if (err == p-buf) {
		ctl->last = now;
		ctl->sent++;
		if (!ctl->unicasting)
			ctl->brd_sent++;
	}
	return err;
}

void finish(void)
{
	struct run_state *ctl = global_ptr;

	if (!ctl->quiet) {
		printf("Sent %d probes (%d broadcast(s))\n", ctl->sent, ctl->brd_sent);
		printf("Received %d response(s)", ctl->received);
		if (ctl->brd_recv || ctl->req_recv) {
			printf(" (");
			if (ctl->req_recv)
				printf("%d request(s)", ctl->req_recv);
			if (ctl->brd_recv)
				printf("%s%d broadcast(s)",
				       ctl->req_recv ? ", " : "",
				       ctl->brd_recv);
			printf(")");
		}
		printf("\n");
		fflush(stdout);
	}
	if (ctl->dad)
		exit(!!ctl->received);
	if (ctl->unsolicited)
		exit(0);
	exit(!ctl->received);
}

static void timespec_sub(struct timespec *a, struct timespec *b,
			 struct timespec *res)
{
	res->tv_sec = a->tv_sec - b->tv_sec;
	res->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (a->tv_nsec < b->tv_nsec) {
		res->tv_sec--;
		res->tv_nsec += 1000000000;
	}
}

static int timespec_later(struct timespec *a, struct timespec *b)
{
	return (a->tv_sec > b->tv_sec) ||
		((a->tv_sec == b->tv_sec) && (a->tv_nsec > b->tv_nsec));
}

void catcher(void)
{
	struct run_state *ctl = global_ptr;
	struct timespec ts, ts_s, ts_o;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ctl->start.tv_sec == 0)
		ctl->start = ts;

	timespec_sub(&ts, &ctl->start, &ts_s);
	ts_o.tv_sec = ctl->timeout;
	ts_o.tv_nsec = 500 * 1000000;

	if (ctl->timeout && timespec_later(&ts_s, &ts_o))
		finish();

	timespec_sub(&ts, &ctl->last, &ts_s);
	ts_o.tv_sec = 0;

	if (ctl->last.tv_sec == 0 || timespec_later(&ts_s, &ts_o)) {
		if (!ctl->timeout && (ctl->sent == ctl->count))
			finish();
		send_pack(ctl);
		if ((ctl->sent == ctl->count) && ctl->unsolicited)
			/* We usually wait for an extra iteration
			 * after sending the last request to see if we
			 * get a reply, but we don't need to in
			 * unsolicited mode */
			finish();
	}
	alarm(ctl->interval);
}

void print_hex(unsigned char *p, int len)
{
	int i;
	for (i=0; i<len; i++) {
		printf("%02X", p[i]);
		if (i != len-1)
			printf(":");
	}
}

int recv_pack(struct run_state *ctl, unsigned char *buf, ssize_t len, struct sockaddr_ll *FROM)
{
	struct timespec ts;
	struct arphdr *ah = (struct arphdr*)buf;
	unsigned char *p = (unsigned char *)(ah+1);
	struct in_addr src_ip, dst_ip;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	/* Filter out wild packets */
	if (FROM->sll_pkttype != PACKET_HOST &&
	    FROM->sll_pkttype != PACKET_BROADCAST &&
	    FROM->sll_pkttype != PACKET_MULTICAST)
		return 0;

	/* Only these types are recognised */
	if (ah->ar_op != htons(ARPOP_REQUEST) &&
	    ah->ar_op != htons(ARPOP_REPLY))
		return 0;

	/* ARPHRD check and this darned FDDI hack here :-( */
	if (ah->ar_hrd != htons(FROM->sll_hatype) &&
	    (FROM->sll_hatype != ARPHRD_FDDI || ah->ar_hrd != htons(ARPHRD_ETHER)))
		return 0;

	/* Protocol must be IP. */
	if (ah->ar_pro != htons(ETH_P_IP))
		return 0;
	if (ah->ar_pln != 4)
		return 0;
	if (ah->ar_hln != ((struct sockaddr_ll *)&ctl->me)->sll_halen)
		return 0;
	if (len < (ssize_t) sizeof(*ah) + 2*(4 + ah->ar_hln))
		return 0;
	memcpy(&src_ip, p+ah->ar_hln, 4);
	memcpy(&dst_ip, p+ah->ar_hln+4+ah->ar_hln, 4);
	if (!ctl->dad) {
		if (src_ip.s_addr != ctl->gdst.s_addr)
			return 0;
		if (ctl->gsrc.s_addr != dst_ip.s_addr)
			return 0;
		if (memcmp(p+ah->ar_hln+4, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ah->ar_hln))
			return 0;
	} else {
		/* DAD packet was:
		   src_ip = 0 (or some src)
		   src_hw = ME
		   dst_ip = tested address
		   dst_hw = <unspec>

		   We fail, if receive request/reply with:
		   src_ip = tested_address
		   src_hw != ME
		   if src_ip in request was not zero, check
		   also that it matches to dst_ip, otherwise
		   dst_ip/dst_hw do not matter.
		 */
		if (src_ip.s_addr != ctl->gdst.s_addr)
			return 0;
		if (memcmp(p, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ((struct sockaddr_ll *)&ctl->me)->sll_halen) == 0)
			return 0;
		if (ctl->gsrc.s_addr && ctl->gsrc.s_addr != dst_ip.s_addr)
			return 0;
	}
	if (!ctl->quiet) {
		int s_printed = 0;
		printf("%s ", FROM->sll_pkttype==PACKET_HOST ? "Unicast" : "Broadcast");
		printf("%s from ", ah->ar_op == htons(ARPOP_REPLY) ? "reply" : "request");
		printf("%s [", inet_ntoa(src_ip));
		print_hex(p, ah->ar_hln);
		printf("] ");
		if (dst_ip.s_addr != ctl->gsrc.s_addr) {
			printf("for %s ", inet_ntoa(dst_ip));
			s_printed = 1;
		}
		if (memcmp(p + ah->ar_hln + 4, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ah->ar_hln)) {
			if (!s_printed)
				printf("for ");
			printf("[");
			print_hex(p+ah->ar_hln+4, ah->ar_hln);
			printf("]");
		}
		if (ctl->last.tv_sec) {
			long usecs = (ts.tv_sec - ctl->last.tv_sec) * 1000000 +
				(ts.tv_nsec - ctl->last.tv_nsec + 500) / 1000;
			long msecs = (usecs+500)/1000;
			usecs -= msecs*1000 - 500;
			printf(" %ld.%03ldms\n", msecs, usecs);
		} else {
			printf(" UNSOLICITED?\n");
		}
		fflush(stdout);
	}
	ctl->received++;
	if (ctl->timeout && (ctl->received == ctl->count))
		finish();
	if (FROM->sll_pkttype != PACKET_HOST)
		ctl->brd_recv++;
	if (ah->ar_op == htons(ARPOP_REQUEST))
		ctl->req_recv++;
	if (ctl->quit_on_reply || (ctl->count == 0 && ctl->received == ctl->sent))
		finish();
	if(!ctl->broadcast_only) {
		memcpy(((struct sockaddr_ll *)&ctl->he)->sll_addr, p, ((struct sockaddr_ll *)&ctl->me)->sll_halen);
		ctl->unicasting = 1;
	}
	return 1;
}

#ifdef USE_SYSFS
union sysfs_devattr_value {
	unsigned long	ulong;
	void		*ptr;
};

enum {
	SYSFS_DEVATTR_IFINDEX,
	SYSFS_DEVATTR_FLAGS,
	SYSFS_DEVATTR_ADDR_LEN,
	SYSFS_DEVATTR_BROADCAST,
	SYSFS_DEVATTR_NUM
};

struct sysfs_devattr_values
{
	char *ifname;
	union sysfs_devattr_value	value[SYSFS_DEVATTR_NUM];
};

static int sysfs_devattr_ulong_dec(char *ptr, struct sysfs_devattr_values *v, unsigned idx);
static int sysfs_devattr_ulong_hex(char *ptr, struct sysfs_devattr_values *v, unsigned idx);
static int sysfs_devattr_macaddr(char *ptr, struct sysfs_devattr_values *v, unsigned idx);

struct sysfs_devattrs {
	const char *name;
	int (*handler)(char *ptr, struct sysfs_devattr_values *v, unsigned int idx);
	int free;
} sysfs_devattrs[SYSFS_DEVATTR_NUM] = {
	[SYSFS_DEVATTR_IFINDEX] = {
		.name		= "ifindex",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_ADDR_LEN] = {
		.name		= "addr_len",
		.handler	= sysfs_devattr_ulong_dec,
	},
	[SYSFS_DEVATTR_FLAGS] = {
		.name		= "flags",
		.handler	= sysfs_devattr_ulong_hex,
	},
	[SYSFS_DEVATTR_BROADCAST] = {
		.name		= "broadcast",
		.handler	= sysfs_devattr_macaddr,
		.free		= 1,
	},
};
#endif

/*
 * find_device()
 *
 * This function checks 1) if the device (if given) is okay for ARP,
 * or 2) find fist appropriate device on the system.
 *
 * Return value:
 *	>0	: Succeeded, and appropriate device not found.
 *		  device.ifindex remains 0.
 *	0	: Succeeded, and approptiate device found.
 *		  device.ifindex is set.
 *	<0	: Failed.  Support not found, or other
 *		: system error.  Try other method.
 *
 * If an appropriate device found, it is recorded inside the
 * "device" variable for later reference.
 *
 * We have several implementations for this.
 *	by_ifaddrs():	requires getifaddr() in glibc, and rtnetlink in
 *			kernel. default and recommended for recent systems.
 *	by_sysfs():	requires libsysfs , and sysfs in kernel.
 *	by_ioctl():	unable to list devices without ipv4 address; this
 *			means, you need to supply the device name for
 *			DAD purpose.
 */
/* Common check for ifa->ifa_flags */
static int check_ifflags(struct run_state const *const ctl, unsigned int ifflags)
{
	if (!(ifflags & IFF_UP)) {
		if (ctl->device.name != NULL) {
			if (!ctl->quiet)
				printf("Interface \"%s\" is down\n", ctl->device.name);
			exit(2);
		}
		return -1;
	}
	if (ifflags & (IFF_NOARP | IFF_LOOPBACK)) {
		if (ctl->device.name != NULL) {
			if (!ctl->quiet)
				printf("Interface \"%s\" is not ARPable\n", ctl->device.name);
			exit(ctl->dad ? 0 : 2);
		}
		return -1;
	}
	return 0;
}

static int find_device_by_ifaddrs(struct run_state *ctl)
{
	int rc;
	struct ifaddrs *ifa0, *ifa;
	int n = 0;

	rc = getifaddrs(&ifa0);
	if (rc) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family != AF_PACKET)
			continue;
		if (ctl->device.name && ifa->ifa_name && strcmp(ifa->ifa_name, ctl->device.name))
			continue;

		if (check_ifflags(ctl, ifa->ifa_flags) < 0)
			continue;

		if (!((struct sockaddr_ll *)ifa->ifa_addr)->sll_halen)
			continue;
		if (!ifa->ifa_broadaddr)
			continue;

		ctl->device.ifa = ifa;

		if (n++)
			break;
	}

	if (n == 1 && ctl->device.ifa) {
		ctl->device.ifindex = if_nametoindex(ctl->device.ifa->ifa_name);
		if (!ctl->device.ifindex) {
			perror("arping: if_nametoindex");
			freeifaddrs(ifa0);
			return -1;
		}
		ctl->device.name  = ctl->device.ifa->ifa_name;
		return 0;
	}
	return 1;
}

#ifdef USE_SYSFS
static void sysfs_devattr_values_init(struct sysfs_devattr_values *v, int do_free)
{
	int i;
	if (do_free) {
		free(v->ifname);
		for (i = 0; i < SYSFS_DEVATTR_NUM; i++) {
			if (sysfs_devattrs[i].free)
				free(v->value[i].ptr);
		}
	}
	memset(v, 0, sizeof(*v));
}

static int sysfs_devattr_ulong(char *ptr, struct sysfs_devattr_values *v, unsigned int idx,
				     unsigned int base)
{
	unsigned long *p;
	char *ep;

	if (!ptr || !v)
		return -1;

	p = &v->value[idx].ulong;
	errno = 0;
	*p = strtoul(ptr, &ep, base);
	if ((*ptr && isspace(*ptr & 0xff)) || errno || (*ep != '\0' && *ep != '\n'))
		goto out;

	return 0;
out:
	return -1;
}

static int sysfs_devattr_ulong_dec(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	int rc = sysfs_devattr_ulong(ptr, v, idx, 10);
	return rc;
}

static int sysfs_devattr_ulong_hex(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	int rc = sysfs_devattr_ulong(ptr, v, idx, 16);
	return rc;
}

static int sysfs_devattr_macaddr(char *ptr, struct sysfs_devattr_values *v, unsigned int idx)
{
	unsigned char *m;
	unsigned int i;
	unsigned int addrlen;

	if (!ptr || !v)
		return -1;

	addrlen = v->value[SYSFS_DEVATTR_ADDR_LEN].ulong;
	m = malloc(addrlen);

	for (i = 0; i < addrlen; i++) {
		if (i && *(ptr + i * 3 - 1) != ':')
			goto out;
		if (sscanf(ptr + i * 3, "%02hhx", &m[i]) != 1)
			goto out;
	}

	v->value[idx].ptr = m;
	return 0;
out:
	free(m);
	return -1;
}
#endif

int find_device_by_sysfs(struct run_state *ctl)
{
	int rc = -1;
#ifdef USE_SYSFS
	DIR *dir;
	struct dirent *dirp;
	struct sysfs_devattr_values sysfs_devattr_values;
	int n = 0;

	if (!ctl->device.sysfs) {
		ctl->device.sysfs = malloc(sizeof(*ctl->device.sysfs));
		sysfs_devattr_values_init(ctl->device.sysfs, 0);
	}
	dir = opendir("/sys/class/net");

	sysfs_devattr_values_init(&sysfs_devattr_values, 0);

	while ((dirp = readdir(dir)) != NULL) {
		int i;
		int ret = -1;

		if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
			continue;
		if (ctl->device.name && strcmp(dirp->d_name, ctl->device.name))
			goto do_next;

		sysfs_devattr_values_init(&sysfs_devattr_values, 1);

		for (i = 0; i < SYSFS_DEVATTR_NUM; i++) {
			char path[PATH_MAX];
			char str[256];
			FILE *f;

			sprintf(path, "/sys/class/net/%s/%s", dirp->d_name, sysfs_devattrs[i].name);
			f = fopen(path, "r");
			if (!f)
				continue;
			if (fscanf(f, "%255s", str) != 1)
				str[0] = '\0';
			fclose(f);
			ret = sysfs_devattrs[i].handler(str, &sysfs_devattr_values, i);

			if (ret < 0)
				break;
		}

		if (ret < 0)
			goto do_next;

		if (check_ifflags(ctl, sysfs_devattr_values.value[SYSFS_DEVATTR_FLAGS].ulong) < 0)
			goto do_next;

		if (!sysfs_devattr_values.value[SYSFS_DEVATTR_ADDR_LEN].ulong)
			goto do_next;

		if (ctl->device.sysfs->value[SYSFS_DEVATTR_IFINDEX].ulong) {
			if (ctl->device.sysfs->value[SYSFS_DEVATTR_FLAGS].ulong & IFF_RUNNING)
				goto do_next;
		}

		sysfs_devattr_values.ifname = strdup(dirp->d_name);
		if (!sysfs_devattr_values.ifname) {
			perror("malloc");
			goto out;
		}

		sysfs_devattr_values_init(ctl->device.sysfs, 1);
		memcpy(ctl->device.sysfs, &sysfs_devattr_values, sizeof(*ctl->device.sysfs));
		sysfs_devattr_values_init(&sysfs_devattr_values, 0);

		if (n++)
			break;

		continue;
do_next:
		sysfs_devattr_values_init(&sysfs_devattr_values, 1);
	}

	if (n == 1) {
		ctl->device.ifindex = ctl->device.sysfs->value[SYSFS_DEVATTR_IFINDEX].ulong;
		ctl->device.name = ctl->device.sysfs->ifname;
	}
	rc = !ctl->device.ifindex;
out:
	closedir(dir);
#endif
	return rc;
}

static int check_device_by_ioctl(struct run_state *ctl, int s, struct ifreq *ifr)
{
	if (ioctl(s, SIOCGIFFLAGS, ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX");
		return -1;
	}

	if (check_ifflags(ctl, ifr->ifr_flags) < 0)
		return 1;

	if (ioctl(s, SIOCGIFINDEX, ifr) < 0) {
		perror("ioctl(SIOCGIFINDEX");
		return -1;
	}

	return 0;
}

static int find_device_by_ioctl(struct run_state *ctl)
{
	int s;
	struct ifreq *ifr0, *ifr, *ifr_end;
	size_t ifrsize = sizeof(*ifr);
	struct ifconf ifc;
	static struct ifreq ifrbuf;
	int n = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifrbuf, 0, sizeof(ifrbuf));

	if (ctl->device.name) {
		strncpy(ifrbuf.ifr_name, ctl->device.name, sizeof(ifrbuf.ifr_name) - 1);
		if (check_device_by_ioctl(ctl, s, &ifrbuf))
			goto out;
		n++;
	} else {
		do {
			int rc;
			ifr0 = malloc(ifrsize);
			if (!ifr0) {
				perror("malloc");
				goto out;
			}

			ifc.ifc_buf = (char *)ifr0;
			ifc.ifc_len = ifrsize;

			rc = ioctl(s, SIOCGIFCONF, &ifc);
			if (rc < 0) {
				perror("ioctl(SIOCFIFCONF");
				goto out;
			}

			if (ifc.ifc_len + sizeof(*ifr0) + sizeof(struct sockaddr_storage) - sizeof(struct sockaddr) <= ifrsize)
				break;
			ifrsize *= 2;
			free(ifr0);
			ifr0 = NULL;
		} while(ifrsize < INT_MAX / 2);

		if (!ifr0) {
			fprintf(stderr, "arping: too many interfaces!?\n");
			goto out;
		}

		ifr_end = (struct ifreq *)(((char *)ifr0) + ifc.ifc_len - sizeof(*ifr0));
		for (ifr = ifr0; ifr <= ifr_end; ifr++) {
			if (check_device_by_ioctl(ctl, s, &ifrbuf))
				continue;
			memcpy(&ifrbuf.ifr_name, ifr->ifr_name, sizeof(ifrbuf.ifr_name));
			if (n++)
				break;
		}
	}

	close(s);

	if (n == 1) {
		ctl->device.ifindex = ifrbuf.ifr_ifindex;
		ctl->device.name = ifrbuf.ifr_name;
	}
	return !ctl->device.ifindex;
out:
	close(s);
	return -1;
}

static int find_device(struct run_state *ctl)
{
	int rc;
	rc = find_device_by_ifaddrs(ctl);
	if (rc >= 0)
		goto out;
	rc = find_device_by_sysfs(ctl);
	if (rc >= 0)
		goto out;
	rc = find_device_by_ioctl(ctl);
out:
	return rc;
}

/*
 * set_device_broadcast()
 *
 * This fills the device "broadcast address"
 * based on information found by find_device() funcion.
 */
static void set_device_broadcast(struct run_state *ctl)
{
	struct sockaddr_ll *he = (struct sockaddr_ll *)&(ctl->he);

	if (ctl->device.ifa) {
		struct sockaddr_ll *sll =
			(struct sockaddr_ll *)ctl->device.ifa->ifa_broadaddr;

		if (sll->sll_halen == he->sll_halen) {
			memcpy(he->sll_addr, sll->sll_addr, he->sll_halen);
			return;
		}
	}
#ifdef USE_SYSFS
	if (ctl->device.sysfs && ctl->device.sysfs->value[SYSFS_DEVATTR_ADDR_LEN].ulong !=
	    he->sll_halen) {
		memcpy(he->sll_addr,
		       ctl->device.sysfs->value[SYSFS_DEVATTR_BROADCAST].ptr,
		       he->sll_halen);
		return;
	}
#endif
	if (!ctl->quiet)
		fprintf(stderr, "WARNING: using default broadcast address.\n");
	memset(he->sll_addr, -1, he->sll_halen);
}

int
main(int argc, char **argv)
{
	struct run_state ctl = {
		.device = { .name = DEFAULT_DEVICE },
		.count = -1,
		.interval = 1,
		0
	};
	int socket_errno;
	int ch;

	global_ptr = &ctl;
#ifdef HAVE_LIBCAP
	limit_capabilities();
#else
	limit_capabilities(&ctl);
#endif


#ifdef USE_IDN
	setlocale(LC_ALL, "");
#endif

	enable_capability_raw(&ctl);

	ctl.socketfd = socket(PF_PACKET, SOCK_DGRAM, 0);
	socket_errno = errno;

	disable_capability_raw(&ctl);

	while ((ch = getopt(argc, argv, "h?bfDUAqc:w:i:s:I:V")) != EOF) {
		switch(ch) {
		case 'b':
			ctl.broadcast_only=1;
			break;
		case 'D':
			ctl.dad = 1;
			ctl.quit_on_reply = 1;
			break;
		case 'U':
			ctl.unsolicited = 1;
			break;
		case 'A':
			ctl.advert = 1;
			ctl.unsolicited = 1;
			break;
		case 'q':
			ctl.quiet = 1;
			break;
		case 'c':
			ctl.count = atoi(optarg);
			break;
		case 'w':
			ctl.timeout = atoi(optarg);
			break;
		case 'i':
			ctl.interval = (unsigned int)atoi(optarg);
			break;
		case 'I':
			ctl.device.name = optarg;
			break;
		case 'f':
			ctl.quit_on_reply = 1;
			break;
		case 's':
			ctl.source = optarg;
			break;
		case 'V':
			printf(IPUTILS_VERSION("arping"));
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	ctl.target = *argv;

	if (ctl.device.name && !*ctl.device.name)
		ctl.device.name = NULL;

	if (ctl.socketfd < 0) {
		errno = socket_errno;
		perror("arping: socket");
		exit(2);
	}

	if (find_device(&ctl) < 0)
		exit(2);

	if (!ctl.device.ifindex) {
		if (ctl.device.name) {
			fprintf(stderr, "arping: Device %s not available.\n", ctl.device.name);
			exit(2);
		}
		fprintf(stderr, "arping: Suitable device could not be determined. Please, use option -I.\n");
		usage();
	}

	if (inet_aton(ctl.target, &ctl.gdst) != 1) {
		struct addrinfo hints = {
			.ai_family = AF_INET,
			.ai_socktype = SOCK_RAW,
#ifdef USE_IDN
			.ai_flags = AI_IDN | AI_CANONIDN
#endif
		};
		struct addrinfo *result;
		int status;

		status = getaddrinfo(ctl.target, NULL, &hints, &result);
		if (status) {
			fprintf(stderr, "arping: %s: %s\n", ctl.target, gai_strerror(status));
			exit(2);
		}

		memcpy(&ctl.gdst, &((struct sockaddr_in *) result->ai_addr)->sin_addr, sizeof ctl.gdst);
		freeaddrinfo(result);
	}

	if (ctl.source && inet_aton(ctl.source, &ctl.gsrc) != 1) {
		fprintf(stderr, "arping: invalid source %s\n", ctl.source);
		exit(2);
	}

	if (!ctl.dad && ctl.unsolicited && ctl.source == NULL)
		ctl.gsrc = ctl.gdst;

	if (!ctl.dad || ctl.source) {
		struct sockaddr_in saddr;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			exit(2);
		}
		if (ctl.device.name) {
			enable_capability_raw(&ctl);

			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, ctl.device.name,
				       strlen(ctl.device.name) + 1) == -1)
				perror("WARNING: interface is ignored");

			disable_capability_raw(&ctl);
		}
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		if (ctl.source || ctl.gsrc.s_addr) {
			saddr.sin_addr = ctl.gsrc;
			if (bind(probe_fd, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
				perror("bind");
				exit(2);
			}
		} else if (!ctl.dad) {
			int on = 1;
			socklen_t alen = sizeof(saddr);

			saddr.sin_port = htons(1025);
			saddr.sin_addr = ctl.gdst;

			if (setsockopt(probe_fd, SOL_SOCKET, SO_DONTROUTE, (char*)&on, sizeof(on)) == -1)
				perror("WARNING: setsockopt(SO_DONTROUTE)");
			if (connect(probe_fd, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
				perror("connect");
				exit(2);
			}
			if (getsockname(probe_fd, (struct sockaddr*)&saddr, &alen) == -1) {
				perror("getsockname");
				exit(2);
			}
			ctl.gsrc = saddr.sin_addr;
		}
		close(probe_fd);
	};

	((struct sockaddr_ll *)&ctl.me)->sll_family = AF_PACKET;
	((struct sockaddr_ll *)&ctl.me)->sll_ifindex = ctl.device.ifindex;
	((struct sockaddr_ll *)&ctl.me)->sll_protocol = htons(ETH_P_ARP);
	if (bind(ctl.socketfd, (struct sockaddr*)&ctl.me, sizeof(ctl.me)) == -1) {
		perror("bind");
		exit(2);
	}

	if (1) {
		socklen_t alen = sizeof(ctl.me);
		if (getsockname(ctl.socketfd, (struct sockaddr*)&ctl.me, &alen) == -1) {
			perror("getsockname");
			exit(2);
		}
	}
	if (((struct sockaddr_ll *)&ctl.me)->sll_halen == 0) {
		if (!ctl.quiet)
			printf("Interface \"%s\" is not ARPable (no ll address)\n", ctl.device.name);
		exit(ctl.dad ? 0 : 2);
	}

	ctl.he = ctl.me;

	set_device_broadcast(&ctl);

	if (!ctl.quiet) {
		printf("ARPING %s ", inet_ntoa(ctl.gdst));
		printf("from %s %s\n",  inet_ntoa(ctl.gsrc), ctl.device.name ? ctl.device.name : "");
	}

	if (!ctl.source && !ctl.gsrc.s_addr && !ctl.dad) {
		fprintf(stderr, "arping: no source address in not-DAD mode\n");
		exit(2);
	}

	drop_capabilities();

	set_signal(SIGINT, finish);
	set_signal(SIGALRM, catcher);

	catcher();

	while(1) {
		sigset_t sset, osset;
		unsigned char packet[4096];
		struct sockaddr_storage from;
		socklen_t alen = sizeof(from);
		ssize_t cc;

		sigemptyset(&sset);
		sigaddset(&sset, SIGALRM);
		sigaddset(&sset, SIGINT);
		/* Unblock SIGALRM so that the previously called alarm()
		 * can prevent recvfrom from blocking forever in case the
		 * inherited procmask is blocking SIGALRM and no packet
		 * is received. */
		sigprocmask(SIG_UNBLOCK, &sset, &osset);

		if ((cc = recvfrom(ctl.socketfd, packet, sizeof(packet), 0,
				   (struct sockaddr *)&from, &alen)) < 0) {
			perror("arping: recvfrom");
			if (errno == ENETDOWN)
				exit(2);
			continue;
		}

		sigprocmask(SIG_BLOCK, &sset, NULL);
		recv_pack(&ctl, packet, cc, (struct sockaddr_ll *)&from);
		sigprocmask(SIG_SETMASK, &osset, NULL);
	}
}


