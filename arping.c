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

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
# include <sys/prctl.h>
#endif

#include "iputils_common.h"

#ifdef DEFAULT_DEVICE
# define DEFAULT_DEVICE_STR	DEFAULT_DEVICE
#else
# define DEFAULT_DEVICE		NULL
#endif

#define FINAL_PACKS		2


struct device {
	char *name;
	int ifindex;
	struct ifaddrs *ifa;
};

struct run_state {
	struct device device;
	char *source;
	struct ifaddrs *ifa0;
	struct in_addr gsrc;
	struct in_addr gdst;
	int gdst_family;
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
#ifdef HAVE_LIBCAP
	cap_flag_value_t cap_raw;
#else
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

#ifdef HAVE_LIBCAP
static const cap_value_t caps[] = { CAP_NET_RAW };
#endif

/*
 * All includes, definitions, struct declarations, and global variables are
 * above.  After this comment all you can find is functions.
 */

__attribute__((const)) static inline size_t sll_len(const size_t halen)
{
	const struct sockaddr_ll unused;
	const size_t len = offsetof(struct sockaddr_ll, sll_addr) + halen;

	if (len < sizeof(unused))
		return sizeof(unused);
	return len;
}

static void usage(void)
{
	fprintf(stderr, _(
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
	));
#ifdef DEFAULT_DEVICE_STR
	fprintf(stderr, "(" DEFAULT_DEVICE_STR ")");
#endif
	fprintf(stderr, _(
				"\n"
		"  -s <source>   source ip address\n"
		"  <destination> dns name or ip address\n"
		"\nFor more details see arping(8).\n"
	));
	exit(2);
}

#ifdef HAVE_LIBCAP
static void limit_capabilities(struct run_state *ctl)
{
	cap_t cap_p;

	cap_p = cap_get_proc();
	if (!cap_p)
		error(-1, errno, "cap_get_proc");

	cap_get_flag(cap_p, CAP_NET_RAW, CAP_PERMITTED, &ctl->cap_raw);

	if (ctl->cap_raw != CAP_CLEAR) {
		if (cap_clear(cap_p) < 0)
			error(-1, errno, "cap_clear");

		cap_set_flag(cap_p, CAP_PERMITTED, 1, caps, CAP_SET);

		if (cap_set_proc(cap_p) < 0) {
			error(0, errno, "cap_set_proc");
			if (errno != EPERM)
				exit(-1);
		}
	}

	if (prctl(PR_SET_KEEPCAPS, 1) < 0)
		error(-1, errno, "prctl");

	if (setuid(getuid()) < 0)
		error(-1, errno, "setuid");

	if (prctl(PR_SET_KEEPCAPS, 0) < 0)
		error(-1, errno, "prctl");

	cap_free(cap_p);
}

static int modify_capability_raw(struct run_state *ctl, int on)
{
	cap_t cap_p;

	if (ctl->cap_raw != CAP_SET)
		return on ? -1 : 0;

	cap_p = cap_get_proc();
	if (!cap_p)
		error(-1, errno, "cap_get_proc");

	cap_set_flag(cap_p, CAP_EFFECTIVE, 1, caps, on ? CAP_SET : CAP_CLEAR);

	if (cap_set_proc(cap_p) < 0)
		error(-1, errno, "cap_set_proc");

	cap_free(cap_p);
	return 0;
}

static void drop_capabilities(void)
{
	cap_t cap_p = cap_init();

	if (!cap_p)
		error(-1, errno, "cap_init");

	if (cap_set_proc(cap_p) < 0)
		error(-1, errno, "cap_set_proc");

	cap_free(cap_p);
}
#else	/* HAVE_LIBCAP */
static void limit_capabilities(struct run_state *ctl)
{
	ctl->euid = geteuid();
}

static int modify_capability_raw(struct run_state *ctl, int on)
{
	if (setuid(on ? ctl->euid : getuid()))
		error(-1, errno, "setuid");
	return 0;
}

static void drop_capabilities(void)
{
	if (setuid(getuid()) < 0)
		error(-1, errno, "setuid");
}
#endif	/* HAVE_LIBCAP */

static inline int enable_capability_raw(struct run_state *ctl)
{
	return modify_capability_raw(ctl, 1);
}

static inline int disable_capability_raw(struct run_state *ctl)
{
	return modify_capability_raw(ctl, 0);
}

static int send_pack(struct run_state *ctl)
{
	int err;
	struct timespec now;
	unsigned char buf[256];
	struct arphdr *ah = (struct arphdr *)buf;
	unsigned char *p = (unsigned char *)(ah + 1);
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
	p += ME->sll_halen;

	memcpy(p, &ctl->gsrc, 4);
	p += 4;

	if (ctl->advert)
		memcpy(p, &ME->sll_addr, ah->ar_hln);
	else
		memcpy(p, &HE->sll_addr, ah->ar_hln);
	p += ah->ar_hln;

	memcpy(p, &ctl->gdst, 4);
	p += 4;

	clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	err = sendto(ctl->socketfd, buf, p - buf, 0, (struct sockaddr *)HE, sll_len(ah->ar_hln));
	if (err == p - buf) {
		ctl->last = now;
		ctl->sent++;
		if (!ctl->unicasting)
			ctl->brd_sent++;
	}
	return err;
}

static int finish(struct run_state *ctl)
{
	if (!ctl->quiet) {
		printf(_("Sent %d probes (%d broadcast(s))\n"), ctl->sent, ctl->brd_sent);
		printf(_("Received %d response(s)"), ctl->received);
		if (ctl->brd_recv || ctl->req_recv) {
			printf(" (");
			if (ctl->req_recv)
				printf(_("%d request(s)"), ctl->req_recv);
			if (ctl->brd_recv)
				printf(_("%s%d broadcast(s)"),
				       ctl->req_recv ? ", " : "",
				       ctl->brd_recv);
			printf(")");
		}
		printf("\n");
		fflush(stdout);
	}
	if (ctl->dad)
		return (!!ctl->received);
	if (ctl->unsolicited)
		return 0;
	return (!ctl->received);
}

static void print_hex(unsigned char *p, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		printf("%02X", p[i]);
		if (i != len - 1)
			printf(":");
	}
}

static int recv_pack(struct run_state *ctl, unsigned char *buf, ssize_t len,
		     struct sockaddr_ll *FROM)
{
	struct timespec ts;
	struct arphdr *ah = (struct arphdr *)buf;
	unsigned char *p = (unsigned char *)(ah + 1);
	struct in_addr src_ip, dst_ip;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

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
	if (len < (ssize_t) sizeof(*ah) + 2 * (4 + ah->ar_hln))
		return 0;
	memcpy(&src_ip, p + ah->ar_hln, 4);
	memcpy(&dst_ip, p + ah->ar_hln + 4 + ah->ar_hln, 4);
	if (!ctl->dad) {
		if (src_ip.s_addr != ctl->gdst.s_addr)
			return 0;
		if (ctl->gsrc.s_addr != dst_ip.s_addr)
			return 0;
		if (memcmp(p + ah->ar_hln + 4, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ah->ar_hln))
			return 0;
	} else {
		/*
		 * DAD packet was:
		 * src_ip = 0 (or some src)
		 * src_hw = ME
		 * dst_ip = tested address
		 * dst_hw = <unspec>
		 *
		 * We fail, if receive request/reply with:
		 * src_ip = tested_address
		 * src_hw != ME
		 * if src_ip in request was not zero, check
		 * also that it matches to dst_ip, otherwise
		 * dst_ip/dst_hw do not matter.
		 */
		if (src_ip.s_addr != ctl->gdst.s_addr)
			return 0;
		if (memcmp(p, ((struct sockaddr_ll *)&ctl->me)->sll_addr,
			   ((struct sockaddr_ll *)&ctl->me)->sll_halen) == 0)
			return 0;
		if (ctl->gsrc.s_addr && ctl->gsrc.s_addr != dst_ip.s_addr)
			return 0;
	}
	if (!ctl->quiet) {
		int s_printed = 0;
		printf("%s ", FROM->sll_pkttype == PACKET_HOST ? _("Unicast") : _("Broadcast"));
		printf(_("%s from "), ah->ar_op == htons(ARPOP_REPLY) ? _("reply") : _("request"));
		printf("%s [", inet_ntoa(src_ip));
		print_hex(p, ah->ar_hln);
		printf("] ");
		if (dst_ip.s_addr != ctl->gsrc.s_addr) {
			printf(_("for %s "), inet_ntoa(dst_ip));
			s_printed = 1;
		}
		if (memcmp(p + ah->ar_hln + 4, ((struct sockaddr_ll *)&ctl->me)->sll_addr, ah->ar_hln)) {
			if (!s_printed)
				printf(_("for "));
			printf("[");
			print_hex(p + ah->ar_hln + 4, ah->ar_hln);
			printf("]");
		}
		if (ctl->last.tv_sec) {
			long usecs = (ts.tv_sec - ctl->last.tv_sec) * 1000000 +
				(ts.tv_nsec - ctl->last.tv_nsec + 500) / 1000;
			long msecs = (usecs + 500) / 1000;
			usecs -= msecs * 1000 - 500;
			printf(_(" %ld.%03ldms\n"), msecs, usecs);
		} else {
			printf(_(" UNSOLICITED?\n"));
		}
		fflush(stdout);
	}
	ctl->received++;
	if (ctl->timeout && (ctl->received == ctl->count))
		return FINAL_PACKS;
	if (FROM->sll_pkttype != PACKET_HOST)
		ctl->brd_recv++;
	if (ah->ar_op == htons(ARPOP_REQUEST))
		ctl->req_recv++;
	if (ctl->quit_on_reply || (ctl->count == 0 && ctl->received == ctl->sent))
		return FINAL_PACKS;
	if (!ctl->broadcast_only) {
		memcpy(((struct sockaddr_ll *)&ctl->he)->sll_addr, p,
		       ((struct sockaddr_ll *)&ctl->me)->sll_halen);
		ctl->unicasting = 1;
	}
	return 1;
}

static int outgoing_device(struct run_state *const ctl, struct nlmsghdr *nh)
{
	struct rtmsg *rm = NLMSG_DATA(nh);
	int len = RTM_PAYLOAD(nh);
	struct rtattr *ra;

	if (nh->nlmsg_type != RTM_NEWROUTE) {
		error(0, 0, "NETLINK new route message type");
		return 1;
	}
	for (ra = RTM_RTA(rm); RTA_OK(ra, len); ra = RTA_NEXT(ra, len)) {
		if (ra->rta_type == RTA_OIF) {
			int *oif = RTA_DATA(ra);
			static char dev_name[IF_NAMESIZE];

			ctl->device.ifindex = *oif;
			if (!if_indextoname(ctl->device.ifindex, dev_name)) {
				error(0, errno, "if_indextoname failed");
				return 1;
			}
			ctl->device.name = dev_name;
		}
	}
	return 0;
}

static void netlink_query(struct run_state *const ctl, const int flags,
			  const int type, void const *const arg, size_t len)
{
	const size_t buffer_size = 4096;
	int fd;
	static uint32_t seq;
	struct msghdr mh = { 0 };
	struct sockaddr_nl sa = {.nl_family = AF_NETLINK };
	struct nlmsghdr *nh, *unmodified_nh;
	struct iovec iov;
	ssize_t msg_len;
	int ret = 1;

	mh.msg_name = (void *)&sa;
	mh.msg_namelen = sizeof(sa);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	unmodified_nh = nh = calloc(1, buffer_size);
	if (!nh)
		error(1, errno, "allocating %zu bytes failed", buffer_size);

	nh->nlmsg_len = NLMSG_LENGTH(len);
	nh->nlmsg_flags = flags;
	nh->nlmsg_type = type;
	nh->nlmsg_seq = ++seq;
	memcpy(NLMSG_DATA(nh), arg, len);

	iov.iov_base = nh;
	iov.iov_len = buffer_size;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		error(0, errno, "NETLINK_ROUTE socket failed");
		goto fail;
	}
	if (sendmsg(fd, &mh, 0) < 0) {
		error(0, errno, "NETLINK_ROUTE socket failed");
		goto fail;
	}
	do {
		msg_len = recvmsg(fd, &mh, 0);
	} while (msg_len < 0 && errno == EINTR);

	for (nh = iov.iov_base; NLMSG_OK(nh, msg_len); nh = NLMSG_NEXT(nh, msg_len)) {
		if (nh->nlmsg_seq != seq)
			continue;
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
		case NLMSG_OVERRUN:
			errno = EIO;
			error(0, 0, "NETLINK_ROUTE unexpected iov element");
			goto fail;
		case NLMSG_DONE:
			ret = 0;
			break;
		default:
			ret = outgoing_device(ctl, nh);
			break;
		}
	}
 fail:
	free(unmodified_nh);
	if (0 <= fd)
		close(fd);
	if (ret)
		exit(1);
}

static void guess_device(struct run_state *const ctl)
{
	size_t addr_len, len;
	struct {
		struct rtmsg rm;
		struct rtattr ra;
		char addr[16];
	} query = { {0}, {0}, {0} };

	switch (ctl->gdst_family) {
	case AF_INET:
		addr_len = 4;
		break;
	case AF_INET6:
		addr_len = 16;
		break;
	default:
		error(1, 0, "unknown address family, please, use option -I.");
		abort();
	}

	query.rm.rtm_family = ctl->gdst_family;
	query.ra.rta_len = RTA_LENGTH(addr_len);
	query.ra.rta_type = RTA_DST;
	memcpy(RTA_DATA(&query.ra), &ctl->gdst, addr_len);
	len = NLMSG_ALIGN(sizeof(struct rtmsg)) + RTA_LENGTH(addr_len);
	netlink_query(ctl, NLM_F_REQUEST, RTM_GETROUTE, &query, len);
}

/* Common check for ifa->ifa_flags */
static int check_ifflags(struct run_state const *const ctl, unsigned int ifflags)
{
	if (!(ifflags & IFF_UP)) {
		if (ctl->device.name != NULL) {
			if (!ctl->quiet)
				printf(_("Interface \"%s\" is down\n"), ctl->device.name);
			exit(2);
		}
		return -1;
	}
	if (ifflags & (IFF_NOARP | IFF_LOOPBACK)) {
		if (ctl->device.name != NULL) {
			if (!ctl->quiet)
				printf(_("Interface \"%s\" is not ARPable\n"), ctl->device.name);
			exit(ctl->dad ? 0 : 2);
		}
		return -1;
	}
	return 0;
}

/*
 * check_device()
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
 *		: system error.
 *
 * If an appropriate device found, it is recorded inside the
 * "device" variable for later reference.
 *
 */
static int check_device(struct run_state *ctl)
{
	int rc;
	struct ifaddrs *ifa;
	int n = 0;

	rc = getifaddrs(&ctl->ifa0);
	if (rc) {
		error(0, errno, "getifaddrs");
		return -1;
	}

	for (ifa = ctl->ifa0; ifa; ifa = ifa->ifa_next) {
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
			error(0, errno, "if_nametoindex");
			freeifaddrs(ctl->ifa0);
			return -1;
		}
		ctl->device.name = ctl->device.ifa->ifa_name;
		return 0;
	}
	return 1;
}

/*
 * find_broadcast_address()
 *
 * This fills the device "broadcast address"
 * based on information found by check_device() function.
 */
static void find_broadcast_address(struct run_state *ctl)
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
	if (!ctl->quiet)
		fprintf(stderr, _("WARNING: using default broadcast address.\n"));
	memset(he->sll_addr, -1, he->sll_halen);
}

static int event_loop(struct run_state *ctl)
{
	int exit_loop = 0, rc = 0;
	ssize_t s;
	enum {
		POLLFD_SIGNAL = 0,
		POLLFD_TIMER,
		POLLFD_SOCKET,
		POLLFD_COUNT
	};
	struct pollfd pfds[POLLFD_COUNT];

	sigset_t mask;
	int sfd;
	struct signalfd_siginfo sigval;

	int tfd;
	struct itimerspec timerfd_vals = {
		.it_interval.tv_sec = ctl->interval,
		.it_interval.tv_nsec = 0,
		.it_value.tv_sec = ctl->interval,
		.it_value.tv_nsec = 0
	};
	uint64_t exp, total_expires = 1;

	unsigned char packet[4096];
	struct sockaddr_storage from = { 0 };
	socklen_t addr_len = sizeof(from);

	/* signalfd */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		error(0, errno, "sigprocmask failed");
		return 1;
	}
	sfd = signalfd(-1, &mask, 0);
	if (sfd == -1) {
		error(0, errno, "signalfd");
		return 1;
	}
	pfds[POLLFD_SIGNAL].fd = sfd;
	pfds[POLLFD_SIGNAL].events = POLLIN | POLLERR | POLLHUP;

	/* timerfd */
	tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (tfd == -1) {
		error(0, errno, "timerfd_create failed");
		return 1;
	}
	if (timerfd_settime(tfd, 0, &timerfd_vals, NULL)) {
		error(0, errno, "timerfd_settime failed");
		return 1;
	}
	pfds[POLLFD_TIMER].fd = tfd;
	pfds[POLLFD_TIMER].events = POLLIN | POLLERR | POLLHUP;

	/* socket */
	pfds[POLLFD_SOCKET].fd = ctl->socketfd;
	pfds[POLLFD_SOCKET].events = POLLIN | POLLERR | POLLHUP;
	send_pack(ctl);

	while (!exit_loop) {
		int ret;
		size_t i;

		ret = poll(pfds, POLLFD_COUNT, -1);
		if (ret <= 0) {
			if (errno == EAGAIN)
				continue;
			if (errno)
				error(0, errno, "poll failed");
			exit_loop = 1;
			continue;
		}

		for (i = 0; i < POLLFD_COUNT; i++) {
			if (pfds[i].revents == 0)
				continue;
			switch (i) {
			case POLLFD_SIGNAL:
				s = read(sfd, &sigval, sizeof(struct signalfd_siginfo));
				if (s != sizeof(struct signalfd_siginfo)) {
					error(0, errno, "could not read signalfd");
					continue;
				}
				if (sigval.ssi_signo == SIGINT || sigval.ssi_signo == SIGQUIT ||
				    sigval.ssi_signo == SIGTERM)
					exit_loop = 1;
				else
					error(0, errno, "unexpected signal: %d", sigval.ssi_signo);
				break;
			case POLLFD_TIMER:
				s = read(tfd, &exp, sizeof(uint64_t));
				if (s != sizeof(uint64_t)) {
					error(0, errno, "could not read timerfd");
					continue;
				}
				total_expires += exp;
				if (0 < ctl->count && (uint64_t)ctl->count < total_expires) {
					exit_loop = 1;
					continue;
				}
				send_pack(ctl);
				break;
			case POLLFD_SOCKET:
				if ((s =
				     recvfrom(ctl->socketfd, packet, sizeof(packet), 0,
					      (struct sockaddr *)&from, &addr_len)) < 0) {
					error(0, errno, "recvfrom");
					if (errno == ENETDOWN)
						rc = 2;
					continue;
				}
				if (recv_pack
				    (ctl, packet, s, (struct sockaddr_ll *)&from) == FINAL_PACKS)
					exit_loop = 1;
				break;
			default:
				abort();
			}
		}
	}
	close(sfd);
	close(tfd);
	freeifaddrs(ctl->ifa0);
	rc |= finish(ctl);
	rc |= (ctl->sent != ctl->received);
	return rc;
}

int main(int argc, char **argv)
{
	struct run_state ctl = {
		.device = { .name = DEFAULT_DEVICE },
		.count = -1,
		.interval = 1,
#ifdef HAVE_LIBCAP
		.cap_raw = CAP_CLEAR,
#endif
		0
	};
	int ch;

	atexit(close_stdout);
	limit_capabilities(&ctl);
#if defined(USE_IDN) || defined(ENABLE_NLS)
	setlocale(LC_ALL, "");
#ifdef ENABLE_NLS
	bindtextdomain (PACKAGE_NAME, LOCALEDIR);
	textdomain (PACKAGE_NAME);
#endif
#endif
	while ((ch = getopt(argc, argv, "h?bfDUAqc:w:i:s:I:V")) != EOF) {
		switch (ch) {
		case 'b':
			ctl.broadcast_only = 1;
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
			ctl.count = strtol_or_err(optarg, _("invalid argument"), 1, INT_MAX);
			break;
		case 'w':
			ctl.timeout = strtol_or_err(optarg, _("invalid argument"), 0, INT_MAX);
			break;
		case 'i':
			ctl.interval = strtol_or_err(optarg, _("invalid argument"), 0, INT_MAX);
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

	enable_capability_raw(&ctl);
	ctl.socketfd = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (ctl.socketfd < 0)
		error(2, errno, "socket");
	disable_capability_raw(&ctl);

	ctl.target = *argv;

	if (ctl.device.name && !*ctl.device.name)
		ctl.device.name = NULL;

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
		if (status)
			error(2, 0, "%s: %s", ctl.target, gai_strerror(status));

		memcpy(&ctl.gdst, &((struct sockaddr_in *)result->ai_addr)->sin_addr, sizeof ctl.gdst);
		ctl.gdst_family = result->ai_family;
		freeaddrinfo(result);
	} else
		ctl.gdst_family = AF_INET;

	if (!ctl.device.name)
		guess_device(&ctl);

	if (check_device(&ctl) < 0)
		exit(2);

	if (!ctl.device.ifindex) {
		if (ctl.device.name)
			error(2, 0, _("Device %s not available."), ctl.device.name);
		error(0, 0, _("Suitable device could not be determined. Please, use option -I."));
	}

	if (ctl.source && inet_aton(ctl.source, &ctl.gsrc) != 1)
		error(2, 0, "invalid source %s", ctl.source);

	if (!ctl.dad && ctl.unsolicited && ctl.source == NULL)
		ctl.gsrc = ctl.gdst;

	if (!ctl.dad || ctl.source) {
		struct sockaddr_in saddr;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0)
			error(2, errno, "socket");
		if (ctl.device.name) {
			enable_capability_raw(&ctl);

			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, ctl.device.name,
				       strlen(ctl.device.name) + 1) == -1)
				error(0, errno, _("WARNING: interface is ignored"));

			disable_capability_raw(&ctl);
		}
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		if (ctl.source || ctl.gsrc.s_addr) {
			saddr.sin_addr = ctl.gsrc;
			if (bind(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1)
				error(2, errno, "bind");
		} else if (!ctl.dad) {
			int on = 1;
			socklen_t alen = sizeof(saddr);

			saddr.sin_port = htons(1025);
			saddr.sin_addr = ctl.gdst;

			if (setsockopt(probe_fd, SOL_SOCKET, SO_DONTROUTE, (char *)&on, sizeof(on)) == -1)
				error(0, errno, _("WARNING: setsockopt(SO_DONTROUTE)"));
			if (connect(probe_fd, (struct sockaddr *)&saddr, sizeof(saddr)) == -1)
				error(2, errno, "connect");
			if (getsockname(probe_fd, (struct sockaddr *)&saddr, &alen) == -1)
				error(2, errno, "getsockname");
			ctl.gsrc = saddr.sin_addr;
		}
		close(probe_fd);
	};

	((struct sockaddr_ll *)&ctl.me)->sll_family = AF_PACKET;
	((struct sockaddr_ll *)&ctl.me)->sll_ifindex = ctl.device.ifindex;
	((struct sockaddr_ll *)&ctl.me)->sll_protocol = htons(ETH_P_ARP);
	if (bind(ctl.socketfd, (struct sockaddr *)&ctl.me, sizeof(ctl.me)) == -1)
		error(2, errno, "bind");
	{
		socklen_t alen = sizeof(ctl.me);

		if (getsockname(ctl.socketfd, (struct sockaddr *)&ctl.me, &alen) == -1)
			error(2, errno, "getsockname");
	}
	if (((struct sockaddr_ll *)&ctl.me)->sll_halen == 0) {
		if (!ctl.quiet)
			printf(_("Interface \"%s\" is not ARPable (no ll address)\n"), ctl.device.name);
		exit(ctl.dad ? 0 : 2);
	}

	ctl.he = ctl.me;

	find_broadcast_address(&ctl);

	if (!ctl.quiet) {
		printf(_("ARPING %s "), inet_ntoa(ctl.gdst));
		printf(_("from %s %s\n"), inet_ntoa(ctl.gsrc), ctl.device.name ? ctl.device.name : "");
	}

	if (!ctl.source && !ctl.gsrc.s_addr && !ctl.dad)
		error(2, errno, _("no source address in not-DAD mode"));

	drop_capabilities();

	return event_loop(&ctl);
}
