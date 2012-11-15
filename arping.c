/*
 * arping.c
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 */

#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <sys/uio.h>
#ifdef CAPABILITIES
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
#include <sysfs/libsysfs.h>
#endif
#include <ifaddrs.h>

#ifdef USE_IDN
#include <idna.h>
#include <locale.h>
#endif

#include "SNAPSHOT.h"

static void usage(void) __attribute__((noreturn));

#ifdef DEFAULT_DEVICE
# define DEFAULT_DEVICE_STR	DEFAULT_DEVICE
#else
# define DEFAULT_DEVICE_STR	"no default"
# define DEFAULT_DEVICE		NULL
#endif

int quit_on_reply=0;
char *device = DEFAULT_DEVICE;
int ifindex;
char *source;
struct in_addr src, dst;
char *target;
int dad, unsolicited, advert;
int quiet;
int count=-1;
int timeout;
int unicasting;
int s;
int broadcast_only;

struct sockaddr_storage me;
struct sockaddr_storage he;

struct timeval start, last;

int sent, brd_sent;
int received, brd_recv, req_recv;

#ifndef CAPABILITIES
static uid_t euid;
#endif

#define MS_TDIFF(tv1,tv2) ( ((tv1).tv_sec-(tv2).tv_sec)*1000 + \
			   ((tv1).tv_usec-(tv2).tv_usec)/1000 )

#define OFFSET_OF(name,ele)	((size_t)(((name *)0)->ele))

static inline socklen_t sll_len(size_t halen)
{
	socklen_t len = OFFSET_OF(struct sockaddr_ll, sll_addr) + halen;
	if (len < sizeof(struct sockaddr_ll))
		len = sizeof(struct sockaddr_ll);
	return len;
}

#define SLL_LEN(hln)		sll_len(hln)

void usage(void)
{
	fprintf(stderr,
		"Usage: arping [-fqbDUAV] [-c count] [-w timeout] [-I device] [-s source] destination\n"
		"  -f : quit on first reply\n"
		"  -q : be quiet\n"
		"  -b : keep broadcasting, don't go unicast\n"
		"  -D : duplicate address detection mode\n"
		"  -U : Unsolicited ARP mode, update your neighbours\n"
		"  -A : ARP answer mode, update your neighbours\n"
		"  -V : print version and exit\n"
		"  -c count : how many packets to send\n"
		"  -w timeout : how long to wait for a reply\n"
		"  -I device : which ethernet device to use (" DEFAULT_DEVICE_STR ")\n"
		"  -s source : source ip address\n"
		"  destination : ask for what ip address\n"
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

#ifdef CAPABILITIES
static const cap_value_t caps[] = { CAP_NET_RAW, };
#endif

void limit_capabilities(void)
{
#ifdef CAPABILITIES
	cap_t cap_p;

	cap_p = cap_init();
	if (!cap_p) {
		perror("arping: cap_init");
		exit(-1);
	}

	if (cap_set_flag(cap_p, CAP_PERMITTED, 1, caps, CAP_SET) < 0) {
		perror("arping: cap_set_flag");
		exit(-1);
	}

	if (cap_set_proc(cap_p) < 0) {
		perror("arping: cap_set_proc");
		if (errno != EPERM)
			exit(-1);
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

	if (cap_free(cap_p) < 0) {
		perror("arping: cap_free");
		exit(-1);
	}
#else
	euid = geteuid();
#endif
}

int modify_capability_raw(int on)
{
#ifdef CAPABILITIES
	cap_t cap_p;

	cap_p = cap_get_proc();
	if (!cap_p) {
		perror("arping: cap_get_proc");
		return -1;
	}

	if (cap_set_flag(cap_p, CAP_EFFECTIVE, 1, caps, on ? CAP_SET : CAP_CLEAR) < 0) {
		perror("arping: cap_set_flag");
		return -1;
	}

	if (cap_set_proc(cap_p) < 0) {
		perror("arping: cap_set_proc");
		return -1;
	}

	if (cap_free(cap_p) < 0) {
		perror("arping: cap_free");
		return -1;
	}
#else
	if (setuid(on ? euid : getuid())) {
		perror("arping: setuid");
		return -1;
	}
#endif
	return 0;
}

static inline int enable_capability_raw(void)
{
	return modify_capability_raw(1);
}

static inline int disable_capability_raw(void)
{
	return modify_capability_raw(0);
}

void drop_capabilities(void)
{
#ifdef CAPABILITIES
	cap_t cap_p = cap_init();

	if (!cap_p) {
		perror("arping: cap_init");
		exit(-1);
	}

	if (cap_set_proc(cap_p) < 0) {
		perror("arping: cap_set_proc");
		exit(-1);
	}

	if (cap_free(cap_p) < 0) {
		perror("arping: cap_free");
		exit(-1);
	}
#else
	if (setuid(getuid()) < 0) {
		perror("arping: setuid");
		exit(-1);
	}
#endif
}

int send_pack(int s, struct in_addr src, struct in_addr dst,
	      struct sockaddr_ll *ME, struct sockaddr_ll *HE)
{
	int err;
	struct timeval now;
	unsigned char buf[256];
	struct arphdr *ah = (struct arphdr*)buf;
	unsigned char *p = (unsigned char *)(ah+1);

	ah->ar_hrd = htons(ME->sll_hatype);
	if (ah->ar_hrd == htons(ARPHRD_FDDI))
		ah->ar_hrd = htons(ARPHRD_ETHER);
	ah->ar_pro = htons(ETH_P_IP);
	ah->ar_hln = ME->sll_halen;
	ah->ar_pln = 4;
	ah->ar_op  = advert ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

	memcpy(p, &ME->sll_addr, ah->ar_hln);
	p+=ME->sll_halen;

	memcpy(p, &src, 4);
	p+=4;

	if (advert)
		memcpy(p, &ME->sll_addr, ah->ar_hln);
	else
		memcpy(p, &HE->sll_addr, ah->ar_hln);
	p+=ah->ar_hln;

	memcpy(p, &dst, 4);
	p+=4;

	gettimeofday(&now, NULL);
	err = sendto(s, buf, p-buf, 0, (struct sockaddr*)HE, SLL_LEN(ah->ar_hln));
	if (err == p-buf) {
		last = now;
		sent++;
		if (!unicasting)
			brd_sent++;
	}
	return err;
}

void finish(void)
{
	if (!quiet) {
		printf("Sent %d probes (%d broadcast(s))\n", sent, brd_sent);
		printf("Received %d response(s)", received);
		if (brd_recv || req_recv) {
			printf(" (");
			if (req_recv)
				printf("%d request(s)", req_recv);
			if (brd_recv)
				printf("%s%d broadcast(s)",
				       req_recv ? ", " : "",
				       brd_recv);
			printf(")");
		}
		printf("\n");
		fflush(stdout);
	}
	if (dad)
		exit(!!received);
	if (unsolicited)
		exit(0);
	exit(!received);
}

void catcher(void)
{
	struct timeval tv, tv_s, tv_o;

	gettimeofday(&tv, NULL);

	if (start.tv_sec==0)
		start = tv;

	timersub(&tv, &start, &tv_s);
	tv_o.tv_sec = timeout;
	tv_o.tv_usec = 500 * 1000;

	if (count-- == 0 || (timeout && timercmp(&tv_s, &tv_o, >)))
		finish();

	timersub(&tv, &last, &tv_s);
	tv_o.tv_sec = 0;

	if (last.tv_sec==0 || timercmp(&tv_s, &tv_o, >)) {
		send_pack(s, src, dst,
			  (struct sockaddr_ll *)&me, (struct sockaddr_ll *)&he);
		if (count == 0 && unsolicited)
			finish();
	}
	alarm(1);
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

int recv_pack(unsigned char *buf, int len, struct sockaddr_ll *FROM)
{
	struct timeval tv;
	struct arphdr *ah = (struct arphdr*)buf;
	unsigned char *p = (unsigned char *)(ah+1);
	struct in_addr src_ip, dst_ip;

	gettimeofday(&tv, NULL);

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
	if (ah->ar_hln != ((struct sockaddr_ll *)&me)->sll_halen)
		return 0;
	if (len < sizeof(*ah) + 2*(4 + ah->ar_hln))
		return 0;
	memcpy(&src_ip, p+ah->ar_hln, 4);
	memcpy(&dst_ip, p+ah->ar_hln+4+ah->ar_hln, 4);
	if (!dad) {
		if (src_ip.s_addr != dst.s_addr)
			return 0;
		if (src.s_addr != dst_ip.s_addr)
			return 0;
		if (memcmp(p+ah->ar_hln+4, ((struct sockaddr_ll *)&me)->sll_addr, ah->ar_hln))
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
		if (src_ip.s_addr != dst.s_addr)
			return 0;
		if (memcmp(p, ((struct sockaddr_ll *)&me)->sll_addr, ((struct sockaddr_ll *)&me)->sll_halen) == 0)
			return 0;
		if (src.s_addr && src.s_addr != dst_ip.s_addr)
			return 0;
	}
	if (!quiet) {
		int s_printed = 0;
		printf("%s ", FROM->sll_pkttype==PACKET_HOST ? "Unicast" : "Broadcast");
		printf("%s from ", ah->ar_op == htons(ARPOP_REPLY) ? "reply" : "request");
		printf("%s [", inet_ntoa(src_ip));
		print_hex(p, ah->ar_hln);
		printf("] ");
		if (dst_ip.s_addr != src.s_addr) {
			printf("for %s ", inet_ntoa(dst_ip));
			s_printed = 1;
		}
		if (memcmp(p+ah->ar_hln+4, ((struct sockaddr_ll *)&me)->sll_addr, ah->ar_hln)) {
			if (!s_printed)
				printf("for ");
			printf("[");
			print_hex(p+ah->ar_hln+4, ah->ar_hln);
			printf("]");
		}
		if (last.tv_sec) {
			long usecs = (tv.tv_sec-last.tv_sec) * 1000000 +
				tv.tv_usec-last.tv_usec;
			long msecs = (usecs+500)/1000;
			usecs -= msecs*1000 - 500;
			printf(" %ld.%03ldms\n", msecs, usecs);
		} else {
			printf(" UNSOLICITED?\n");
		}
		fflush(stdout);
	}
	received++;
	if (FROM->sll_pkttype != PACKET_HOST)
		brd_recv++;
	if (ah->ar_op == htons(ARPOP_REQUEST))
		req_recv++;
	if (quit_on_reply)
		finish();
	if(!broadcast_only) {
		memcpy(((struct sockaddr_ll *)&he)->sll_addr, p, ((struct sockaddr_ll *)&me)->sll_halen);
		unicasting=1;
	}
	return 1;
}

#if USE_SYSFS
static int set_device_broadcast_sysfs(char *device, unsigned char *ba, size_t balen)
{
	struct sysfs_class_device *dev;
	struct sysfs_attribute *brdcast;
	unsigned char *p;
	int ch;

	dev = sysfs_open_class_device("net", device);
	if (!dev) {
		perror("sysfs_open_class_device(net)");
		return -1;
	}

	brdcast = sysfs_get_classdev_attr(dev, "broadcast");
	if (!brdcast) {
		perror("sysfs_get_classdev_attr(broadcast)");
		return -1;
	}

	if (sysfs_read_attribute(brdcast)) {
		perror("sysfs_read_attribute");
		return -1;
	}

	for (p = ba, ch = 0; p < ba + balen; p++, ch += 3)
		*p = strtoul(brdcast->value + ch, NULL, 16);

	return 0;
}
#endif

static int set_device_broadcast_ifaddrs(char *device, unsigned char *ba, size_t balen)
{
	struct ifaddrs *ifa0, *ifa;

	if (getifaddrs(&ifa0) < 0) {
		fprintf(stderr, "getifaddrs failed");
		return -1;
	}

	for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
		struct sockaddr_ll *sll;

		if (strcmp(ifa->ifa_name, device) ||
		    !ifa->ifa_addr ||
		    ifa->ifa_addr->sa_family != AF_PACKET ||
		    !(ifa->ifa_flags & IFF_BROADCAST))
			continue;

		sll = (struct sockaddr_ll *)ifa->ifa_broadaddr;

		if (sll->sll_halen != balen)
			continue;

		memcpy(ba, sll->sll_addr, sll->sll_halen);

		break;
	}

	return 0;
}

static int set_device_broadcast_fallback(char *device, unsigned char *ba, size_t balen)
{
	memset(ba, -1, balen);
	return 0;
}

static void set_device_broadcast(char *device, unsigned char *ba, size_t balen)
{

#if USE_SYSFS
	if (!set_device_broadcast_sysfs(device, ba, balen))
		return;
#endif
	if (!set_device_broadcast_ifaddrs(device, ba, balen))
		return;

	set_device_broadcast_fallback(device, ba, balen);
}

static int check_ifflags(unsigned int ifflags, int fatal)
{
	if (!(ifflags & IFF_UP)) {
		if (fatal) {
			if (!quiet)
				printf("Interface \"%s\" is down\n", device);
			exit(2);
		}
		return -1;
	}
	if (ifflags & (IFF_NOARP | IFF_LOOPBACK)) {
		if (fatal) {
			if (!quiet)
				printf("Interface \"%s\" is not ARPable\n", device);
			exit(dad ? 0 : 2);
		}
		return -1;
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int socket_errno;
	int ch;

	limit_capabilities();

#ifdef USE_IDN
	setlocale(LC_ALL, "");
#endif

	enable_capability_raw();

	s = socket(PF_PACKET, SOCK_DGRAM, 0);
	socket_errno = errno;

	disable_capability_raw();

	while ((ch = getopt(argc, argv, "h?bfDUAqc:w:s:I:V")) != EOF) {
		switch(ch) {
		case 'b':
			broadcast_only=1;
			break;
		case 'D':
			dad++;
			quit_on_reply=1;
			break;
		case 'U':
			unsolicited++;
			break;
		case 'A':
			advert++;
			unsolicited++;
			break;
		case 'q':
			quiet++;
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'w':
			timeout = atoi(optarg);
			break;
		case 'I':
			if (!*optarg) {
				fprintf(stderr, "arping: device name cannot be emptry string.\n");
				exit(2);
			}
			device = optarg;
			break;
		case 'f':
			quit_on_reply=1;
			break;
		case 's':
			source = optarg;
			break;
		case 'V':
			printf("arping utility, iputils-%s\n", SNAPSHOT);
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

	target = *argv;

	if (device && !*device)
		device = NULL;

	if (device == NULL) {
		fprintf(stderr, "arping: device (option -I) is required\n");
		usage();
	}

	if (s < 0) {
		errno = socket_errno;
		perror("arping: socket");
		exit(2);
	}

	if (1) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
		if (ioctl(s, SIOCGIFINDEX, &ifr) < 0) {
			fprintf(stderr, "arping: unknown iface %s\n", device);
			exit(2);
		}
		ifindex = ifr.ifr_ifindex;

		if (ioctl(s, SIOCGIFFLAGS, (char*)&ifr)) {
			perror("ioctl(SIOCGIFFLAGS)");
			exit(2);
		}

		check_ifflags(ifr.ifr_flags, 1);
	}

	if (inet_aton(target, &dst) != 1) {
		struct hostent *hp;
		char *idn = target;
#ifdef USE_IDN
		int rc;

		rc = idna_to_ascii_lz(target, &idn, 0);

		if (rc != IDNA_SUCCESS) {
			fprintf(stderr, "arping: IDN encoding failed: %s\n", idna_strerror(rc));
			exit(2);
		}
#endif

		hp = gethostbyname2(idn, AF_INET);
		if (!hp) {
			fprintf(stderr, "arping: unknown host %s\n", target);
			exit(2);
		}

#ifdef USE_IDN
		free(idn);
#endif

		memcpy(&dst, hp->h_addr, 4);
	}

	if (source && inet_aton(source, &src) != 1) {
		fprintf(stderr, "arping: invalid source %s\n", source);
		exit(2);
	}

	if (!dad && unsolicited && src.s_addr == 0)
		src = dst;

	if (!dad || src.s_addr) {
		struct sockaddr_in saddr;
		int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (probe_fd < 0) {
			perror("socket");
			exit(2);
		}
		if (device) {
			enable_capability_raw();

			if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device)+1) == -1)
				perror("WARNING: interface is ignored");

			disable_capability_raw();
		}
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		if (src.s_addr) {
			saddr.sin_addr = src;
			if (bind(probe_fd, (struct sockaddr*)&saddr, sizeof(saddr)) == -1) {
				perror("bind");
				exit(2);
			}
		} else if (!dad) {
			int on = 1;
			socklen_t alen = sizeof(saddr);

			saddr.sin_port = htons(1025);
			saddr.sin_addr = dst;

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
			src = saddr.sin_addr;
		}
		close(probe_fd);
	};

	((struct sockaddr_ll *)&me)->sll_family = AF_PACKET;
	((struct sockaddr_ll *)&me)->sll_ifindex = ifindex;
	((struct sockaddr_ll *)&me)->sll_protocol = htons(ETH_P_ARP);
	if (bind(s, (struct sockaddr*)&me, sizeof(me)) == -1) {
		perror("bind");
		exit(2);
	}

	if (1) {
		socklen_t alen = sizeof(me);
		if (getsockname(s, (struct sockaddr*)&me, &alen) == -1) {
			perror("getsockname");
			exit(2);
		}
	}
	if (((struct sockaddr_ll *)&me)->sll_halen == 0) {
		if (!quiet)
			printf("Interface \"%s\" is not ARPable (no ll address)\n", device);
		exit(dad?0:2);
	}

	he = me;

	set_device_broadcast(device, ((struct sockaddr_ll *)&he)->sll_addr,
			     ((struct sockaddr_ll *)&he)->sll_halen);

	if (!quiet) {
		printf("ARPING %s ", inet_ntoa(dst));
		printf("from %s %s\n",  inet_ntoa(src), device ? : "");
	}

	if (!src.s_addr && !dad) {
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
		int cc;

		if ((cc = recvfrom(s, packet, sizeof(packet), 0,
				   (struct sockaddr *)&from, &alen)) < 0) {
			perror("arping: recvfrom");
			continue;
		}

		sigemptyset(&sset);
		sigaddset(&sset, SIGALRM);
		sigaddset(&sset, SIGINT);
		sigprocmask(SIG_BLOCK, &sset, &osset);
		recv_pack(packet, cc, (struct sockaddr_ll *)&from);
		sigprocmask(SIG_SETMASK, &osset, NULL);
	}
}


