/*
 * Rdisc (this program) was developed by Sun Microsystems, Inc. and is
 * provided for unrestricted use provided that this legend is included on
 * all tape media and as a part of the software program in whole or part.
 * Users may copy or modify Rdisc without charge, and they may freely
 * distribute it.
 *
 * RDISC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Rdisc is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY RDISC
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
/* Do not use "improved" glibc version! */
#include <linux/limits.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/file.h>
#include <malloc.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/*
 * The next include contains all defs and structures for multicast
 * that are not in SunOS 4.1.x. On a SunOS 4.1.x system none of this code
 * is ever used because it does not support multicast
 * Fraser Gardiner - Sun Microsystems Australia
 */

#include <netdb.h>
#include <arpa/inet.h>

#include <string.h>
#include <syslog.h>

#include "SNAPSHOT.h"

struct interface
{
	struct in_addr 	address;	/* Used to identify the interface */
	struct in_addr	localaddr;	/* Actual address if the interface */
	int 		preference;
	int		flags;
	struct in_addr	bcastaddr;
	struct in_addr	remoteaddr;
	struct in_addr	netmask;
	int		ifindex;
	char		name[IFNAMSIZ];
};

/*
 * TBD
 *	Use 255.255.255.255 for broadcasts - not the interface broadcast
 *	address.
 */

#define ALLIGN(ptr)	(ptr)

static int join(int sock, struct sockaddr_in *sin);
static void solicitor(struct sockaddr_in *);
#ifdef RDISC_SERVER
static void advertise(struct sockaddr_in *, int lft);
#endif
static char *pr_name(struct in_addr addr);
static void pr_pack(char *buf, int cc, struct sockaddr_in *from);
static void age_table(int time);
static void record_router(struct in_addr router, int preference, int ttl);
static void add_route(struct in_addr addr);
static void del_route(struct in_addr addr);
static void rtioctl(struct in_addr addr, int op);
static int support_multicast(void);
static int sendbcast(int s, char *packet, int packetlen);
static int sendmcast(int s, char *packet, int packetlen, struct sockaddr_in *);
static int sendbcastif(int s, char *packet, int packetlen, struct interface *ifp);
static int sendmcastif(int s, char *packet, int packetlen, struct sockaddr_in *sin, struct interface *ifp);
static int is_directly_connected(struct in_addr in);
static void initlog(void);
static void discard_table(void);
static void init(void);

#define ICMP_ROUTER_ADVERTISEMENT	9
#define ICMP_ROUTER_SOLICITATION	10

#define ALL_HOSTS_ADDRESS		"224.0.0.1"
#define ALL_ROUTERS_ADDRESS		"224.0.0.2"

#define MAXIFS 32

#if defined(__GLIBC__) && __GLIBC__ < 2
/* For router advertisement */
struct icmp_ra
{
	unsigned char	icmp_type;		/* type of message, see below */
	unsigned char	icmp_code;		/* type sub code */
	unsigned short	icmp_cksum;		/* ones complement cksum of struct */
	unsigned char	icmp_num_addrs;
	unsigned char	icmp_wpa;		/* Words per address */
	short 	icmp_lifetime;
};

struct icmp_ra_addr
{
	__u32	ira_addr;
	__u32	ira_preference;
};
#else
#define icmp_ra icmp
#endif

/* Router constants */
#define	MAX_INITIAL_ADVERT_INTERVAL	16
#define	MAX_INITIAL_ADVERTISEMENTS  	3
#define	MAX_RESPONSE_DELAY		2	/* Not used */

/* Host constants */
#define MAX_SOLICITATIONS 		3
#define SOLICITATION_INTERVAL 		3
#define MAX_SOLICITATION_DELAY		1	/* Not used */

#define INELIGIBLE_PREF			0x80000000	/* Maximum negative */

#define MAX_ADV_INT 600

/* Statics */
static int num_interfaces;

static struct interface *interfaces;
static int interfaces_size;			/* Number of elements in interfaces */


#define	MAXPACKET	4096	/* max packet size */

/* fraser */
int debugfile;

const char usage[] =
"Usage:	rdisc [-b] [-d] [-s] [-v] [-f] [-a] [-V] [send_address] [receive_address]\n"
#ifdef RDISC_SERVER
"       rdisc -r [-b] [-d] [-s] [-v] [-f] [-a] [-V] [-p <preference>] [-T <secs>]\n"
"		 [send_address] [receive_address]\n"
#endif
;


int s;			/* Socket file descriptor */
struct sockaddr_in whereto;/* Address to send to */

/* Common variables */
int verbose = 0;
int debug = 0;
int trace = 0;
int solicit = 0;
int ntransmitted = 0;
int nreceived = 0;
int forever = 0;	/* Never give up on host. If 0 defer fork until
			 * first response.
			 */

#ifdef RDISC_SERVER
/* Router variables */
int responder;
int max_adv_int = MAX_ADV_INT;
int min_adv_int;
int lifetime;
int initial_advert_interval = MAX_INITIAL_ADVERT_INTERVAL;
int initial_advertisements = MAX_INITIAL_ADVERTISEMENTS;
int preference = 0;		/* Setable with -p option */
#endif

/* Host variables */
int max_solicitations = MAX_SOLICITATIONS;
unsigned int solicitation_interval = SOLICITATION_INTERVAL;
int best_preference = 1;  	/* Set to record only the router(s) with the
				   best preference in the kernel. Not set
				   puts all routes in the kernel. */


static void graceful_finish(void);
static void finish(void);
static void timer(void);
static void initifs(void);
static unsigned short in_cksum(unsigned short *addr, int len);

static int logging = 0;

#define logerr(fmt...) ({ if (logging) syslog(LOG_ERR, fmt); \
			  else fprintf(stderr, fmt); })
#define logtrace(fmt...) ({ if (logging) syslog(LOG_INFO, fmt); \
			  else fprintf(stderr, fmt); })
#define logdebug(fmt...) ({ if (logging) syslog(LOG_DEBUG, fmt); \
			  else fprintf(stderr, fmt); })
static void logperror(char *str);

static __inline__ int isbroadcast(struct sockaddr_in *sin)
{
	return (sin->sin_addr.s_addr == INADDR_BROADCAST);
}

static __inline__ int ismulticast(struct sockaddr_in *sin)
{
	return IN_CLASSD(ntohl(sin->sin_addr.s_addr));
}

static void prusage(void)
{
	fputs(usage, stderr);
	exit(1);
}

void do_fork(void)
{
	int t;
	pid_t pid;
	long open_max;

	if (trace)
		return;
	if ((open_max = sysconf(_SC_OPEN_MAX)) == -1) {
		if (errno == 0) {
			(void) fprintf(stderr, "OPEN_MAX is not supported\n");
		} 
		else {
			(void) fprintf(stderr, "sysconf() error\n");
		}
		exit(1);
	}


	if ((pid=fork()) != 0)
		exit(0);

	for (t = 0; t < open_max; t++)
		if (t != s)
			close(t);

	setsid();
	initlog();
}

void signal_setup(int signo, void (*handler)(void))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	sa.sa_handler = (void (*)(int))handler;
#ifdef SA_INTERRUPT
	sa.sa_flags = SA_INTERRUPT;
#endif
	sigaction(signo, &sa, NULL);
}

/*
 * 			M A I N
 */
char    *sendaddress, *recvaddress;

int main(int argc, char **argv)
{
	struct sockaddr_in from;
	char **av = argv;
	struct sockaddr_in *to = &whereto;
	struct sockaddr_in joinaddr;
	sigset_t sset, sset_empty;
#ifdef RDISC_SERVER
	int val;

	min_adv_int =( max_adv_int * 3 / 4);
	lifetime = (3*max_adv_int);
#endif

	argc--, av++;
	while (argc > 0 && *av[0] == '-') {
		while (*++av[0]) {
			switch (*av[0]) {
			case 'd':
				debug = 1;
				break;
			case 't':
				trace = 1;
				break;
			case 'v':
				verbose++;
				break;
			case 's':
				solicit = 1;
				break;
#ifdef RDISC_SERVER
			case 'r':
				responder = 1;
				break;
#endif
			case 'a':
				best_preference = 0;
				break;
			case 'b':
				best_preference = 1;
				break;
			case 'f':
				forever = 1;
				break;
			case 'V':
				printf("rdisc utility, iputils-%s\n", SNAPSHOT);
				exit(0);
#ifdef RDISC_SERVER
			case 'T':
				argc--, av++;
				if (argc != 0) {
					val = strtol(av[0], (char **)NULL, 0);
					if (val < 4 || val > 1800) {
						(void) fprintf(stderr,
							       "Bad Max Advertizement Interval\n");
						exit(1);
					}
					max_adv_int = val;
					min_adv_int =( max_adv_int * 3 / 4);
					lifetime = (3*max_adv_int);
				} else {
					prusage();
					/* NOTREACHED*/
				}
				goto next;
			case 'p':
				argc--, av++;
				if (argc != 0) {
					val = strtol(av[0], (char **)NULL, 0);
					preference = val;
				} else {
					prusage();
					/* NOTREACHED*/
				}
				goto next;
#endif
			default:
				prusage();
				/* NOTREACHED*/
			}
		}
#ifdef RDISC_SERVER
next:
#endif
		argc--, av++;
	}
	if( argc < 1)  {
		if (support_multicast()) {
			sendaddress = ALL_ROUTERS_ADDRESS;
#ifdef RDISC_SERVER
			if (responder)
				sendaddress = ALL_HOSTS_ADDRESS;
#endif
		} else
			sendaddress = "255.255.255.255";
	} else {
		sendaddress = av[0];
		argc--;
	}

	if (argc < 1) {
		if (support_multicast()) {
			recvaddress = ALL_HOSTS_ADDRESS;
#ifdef RDISC_SERVER
			if (responder)
				recvaddress = ALL_ROUTERS_ADDRESS;
#endif
		} else
			recvaddress = "255.255.255.255";
	} else {
		recvaddress = av[0];
		argc--;
	}
	if (argc != 0) {
		(void) fprintf(stderr, "Extra parameters\n");
		prusage();
		/* NOTREACHED */
	}

#ifdef RDISC_SERVER
	if (solicit && responder) {
		prusage();
		/* NOTREACHED */
	}
#endif

	if (!(solicit && !forever)) {
		do_fork();
/*
 * Added the next line to stop forking a second time
 * Fraser Gardiner - Sun Microsystems Australia
 */
		forever = 1;
	}

	memset( (char *)&whereto, 0, sizeof(struct sockaddr_in) );
	to->sin_family = AF_INET;
	to->sin_addr.s_addr = inet_addr(sendaddress);

	memset( (char *)&joinaddr, 0, sizeof(struct sockaddr_in) );
	joinaddr.sin_family = AF_INET;
	joinaddr.sin_addr.s_addr = inet_addr(recvaddress);

#ifdef RDISC_SERVER
	if (responder)
		srandom((int)gethostid());
#endif

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		logperror("socket");
		exit(5);
	}

	setlinebuf( stdout );

	signal_setup(SIGINT, finish );
	signal_setup(SIGTERM, graceful_finish );
	signal_setup(SIGHUP, initifs );
	signal_setup(SIGALRM, timer );

	sigemptyset(&sset);
	sigemptyset(&sset_empty);
	sigaddset(&sset, SIGALRM);
	sigaddset(&sset, SIGHUP);
	sigaddset(&sset, SIGTERM);
	sigaddset(&sset, SIGINT);

	init();
	if (join(s, &joinaddr) < 0) {
		logerr("Failed joining addresses\n");
		exit (2);
	}

	timer();	/* start things going */

	for (;;) {
		unsigned char	packet[MAXPACKET];
		int len = sizeof (packet);
		socklen_t fromlen = sizeof (from);
		int cc;

		cc=recvfrom(s, (char *)packet, len, 0,
			    (struct sockaddr *)&from, &fromlen);
		if (cc<0) {
			if (errno == EINTR)
				continue;
			logperror("recvfrom");
			continue;
		}

		sigprocmask(SIG_SETMASK, &sset, NULL);
		pr_pack( (char *)packet, cc, &from );
		sigprocmask(SIG_SETMASK, &sset_empty, NULL);
	}
	/*NOTREACHED*/
}

#define TIMER_INTERVAL 	3
#define GETIFCONF_TIMER	30

static int left_until_advertise;

/* Called every TIMER_INTERVAL */
void timer()
{
	static int time;
	static int left_until_getifconf;
	static int left_until_solicit;


	time += TIMER_INTERVAL;

	left_until_getifconf -= TIMER_INTERVAL;
	left_until_advertise -= TIMER_INTERVAL;
	left_until_solicit -= TIMER_INTERVAL;

	if (left_until_getifconf < 0) {
		initifs();
		left_until_getifconf = GETIFCONF_TIMER;
	}
#ifdef RDISC_SERVER
	if (responder && left_until_advertise <= 0) {
		ntransmitted++;
		advertise(&whereto, lifetime);
		if (ntransmitted < initial_advertisements)
			left_until_advertise = initial_advert_interval;
		else
			left_until_advertise = min_adv_int +
				((max_adv_int - min_adv_int) *
				 (random() % 1000)/1000);
	} else
#endif
	if (solicit && left_until_solicit <= 0) {
		ntransmitted++;
		solicitor(&whereto);
		if (ntransmitted < max_solicitations)
			left_until_solicit = solicitation_interval;
		else {
			solicit = 0;
			if (!forever && nreceived == 0)
				exit(5);
		}
	}
	age_table(TIMER_INTERVAL);
	alarm(TIMER_INTERVAL);
}

/*
 * 			S O L I C I T O R
 *
 * Compose and transmit an ICMP ROUTER SOLICITATION REQUEST packet.
 * The IP packet will be added on by the kernel.
 */
void
solicitor(struct sockaddr_in *sin)
{
	static unsigned char outpack[MAXPACKET];
	struct icmphdr *icp = (struct icmphdr *) ALLIGN(outpack);
	int packetlen, i;

	if (verbose) {
		logtrace("Sending solicitation to %s\n",
			 pr_name(sin->sin_addr));
	}
	icp->type = ICMP_ROUTER_SOLICITATION;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.gateway = 0; /* Reserved */
	packetlen = 8;

	/* Compute ICMP checksum here */
	icp->checksum = in_cksum( (unsigned short *)icp, packetlen );

	if (isbroadcast(sin))
		i = sendbcast(s, (char *)outpack, packetlen);
	else if (ismulticast(sin))
		i = sendmcast(s, (char *)outpack, packetlen, sin);
	else
		i = sendto( s, (char *)outpack, packetlen, 0,
			   (struct sockaddr *)sin, sizeof(struct sockaddr));

	if( i < 0 || i != packetlen )  {
		if( i<0 ) {
		    logperror("solicitor:sendto");
		}
		logerr("wrote %s %d chars, ret=%d\n",
			sendaddress, packetlen, i );
	}
}

#ifdef RDISC_SERVER
/*
 * 			A V E R T I S E
 *
 * Compose and transmit an ICMP ROUTER ADVERTISEMENT packet.
 * The IP packet will be added on by the kernel.
 */
void
advertise(struct sockaddr_in *sin, int lft)
{
	static unsigned char outpack[MAXPACKET];
	struct icmp_ra *rap = (struct icmp_ra *) ALLIGN(outpack);
	struct icmp_ra_addr *ap;
	int packetlen, i, cc;

	if (verbose) {
		logtrace("Sending advertisement to %s\n",
			 pr_name(sin->sin_addr));
	}

	for (i = 0; i < num_interfaces; i++) {
		rap->icmp_type = ICMP_ROUTER_ADVERTISEMENT;
		rap->icmp_code = 0;
		rap->icmp_cksum = 0;
		rap->icmp_num_addrs = 0;
		rap->icmp_wpa = 2;
		rap->icmp_lifetime = htons(lft);
		packetlen = 8;

		/*
		 * TODO handle multiple logical interfaces per
		 * physical interface. (increment with rap->icmp_wpa * 4 for
		 * each address.)
		 */
		ap = (struct icmp_ra_addr *)ALLIGN(outpack + ICMP_MINLEN);
		ap->ira_addr = interfaces[i].localaddr.s_addr;
		ap->ira_preference = htonl(interfaces[i].preference);
		packetlen += rap->icmp_wpa * 4;
		rap->icmp_num_addrs++;

		/* Compute ICMP checksum here */
		rap->icmp_cksum = in_cksum( (unsigned short *)rap, packetlen );

		if (isbroadcast(sin))
			cc = sendbcastif(s, (char *)outpack, packetlen,
					&interfaces[i]);
		else if (ismulticast(sin))
			cc = sendmcastif( s, (char *)outpack, packetlen, sin,
					&interfaces[i]);
		else {
			struct interface *ifp = &interfaces[i];
			/*
			 * Verify that the interface matches the destination
			 * address.
			 */
			if ((sin->sin_addr.s_addr & ifp->netmask.s_addr) ==
			    (ifp->address.s_addr & ifp->netmask.s_addr)) {
				if (debug) {
					logdebug("Unicast to %s ",
						 pr_name(sin->sin_addr));
					logdebug("on interface %s, %s\n",
						 ifp->name,
						 pr_name(ifp->address));
				}
				cc = sendto( s, (char *)outpack, packetlen, 0,
					    (struct sockaddr *)sin,
					    sizeof(struct sockaddr));
			} else
				cc = packetlen;
		}
		if( cc < 0 || cc != packetlen )  {
			if (cc < 0) {
				logperror("sendto");
			} else {
				logerr("wrote %s %d chars, ret=%d\n",
				       sendaddress, packetlen, cc );
			}
		}
	}
}
#endif

/*
 * 			P R _ T Y P E
 *
 * Convert an ICMP "type" field to a printable string.
 */
char *
pr_type(int t)
{
	static char *ttab[] = {
		"Echo Reply",
		"ICMP 1",
		"ICMP 2",
		"Dest Unreachable",
		"Source Quench",
		"Redirect",
		"ICMP 6",
		"ICMP 7",
		"Echo",
		"Router Advertise",
		"Router Solicitation",
		"Time Exceeded",
		"Parameter Problem",
		"Timestamp",
		"Timestamp Reply",
		"Info Request",
		"Info Reply",
		"Netmask Request",
		"Netmask Reply"
	};

	if ( t < 0 || t > 16 )
		return("OUT-OF-RANGE");

	return(ttab[t]);
}

/*
 *			P R _ N A M E
 *
 * Return a string name for the given IP address.
 */
char *pr_name(struct in_addr addr)
{
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr = addr };
	char hnamebuf[NI_MAXHOST] = "";
	static char buf[80];

	getnameinfo((struct sockaddr *) &sin, sizeof sin, hnamebuf, sizeof hnamebuf, NULL, 0, 0);
	snprintf(buf, sizeof buf, "%s (%s)", hnamebuf, inet_ntoa(addr));
	return(buf);
}

/*
 *			P R _ P A C K
 *
 * Print out the packet, if it came from us.  This logic is necessary
 * because ALL readers of the ICMP socket get a copy of ALL ICMP packets
 * which arrive ('tis only fair).  This permits multiple copies of this
 * program to be run without having intermingled output (or statistics!).
 */
void
pr_pack(char *buf, int cc, struct sockaddr_in *from)
{
	struct iphdr *ip;
	struct icmphdr *icp;
	int i;
	int hlen;

	ip = (struct iphdr *) ALLIGN(buf);
	hlen = ip->ihl << 2;
	if (cc < hlen + 8) {
		if (verbose)
			logtrace("packet too short (%d bytes) from %s\n", cc,
				 pr_name(from->sin_addr));
		return;
	}
	cc -= hlen;
	icp = (struct icmphdr *)ALLIGN(buf + hlen);

	switch (icp->type) {
	case ICMP_ROUTER_ADVERTISEMENT:
	{
		struct icmp_ra *rap = (struct icmp_ra *)ALLIGN(icp);
		struct icmp_ra_addr *ap;

#ifdef RDISC_SERVER
		if (responder)
			break;
#endif

		/* TBD verify that the link is multicast or broadcast */
		/* XXX Find out the link it came in over? */
		if (in_cksum((unsigned short *)ALLIGN(buf+hlen), cc)) {
			if (verbose)
				logtrace("ICMP %s from %s: Bad checksum\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr));
			return;
		}
		if (rap->icmp_code != 0) {
			if (verbose)
				logtrace("ICMP %s from %s: Code = %d\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr),
					 rap->icmp_code);
			return;
		}
		if (rap->icmp_num_addrs < 1) {
			if (verbose)
				logtrace("ICMP %s from %s: No addresses\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr));
			return;
		}
		if (rap->icmp_wpa < 2) {
			if (verbose)
				logtrace("ICMP %s from %s: Words/addr = %d\n",
					 pr_type((int)rap->icmp_type),
					 pr_name(from->sin_addr),
					 rap->icmp_wpa);
			return;
		}
		if ((unsigned)cc <
		    8 + rap->icmp_num_addrs * rap->icmp_wpa * 4) {
			if (verbose)
				logtrace("ICMP %s from %s: Too short %d, %d\n",
					      pr_type((int)rap->icmp_type),
					      pr_name(from->sin_addr),
					      cc,
					      8 + rap->icmp_num_addrs * rap->icmp_wpa * 4);
			return;
		}

		if (verbose)
			logtrace("ICMP %s from %s, lifetime %d\n",
				      pr_type((int)rap->icmp_type),
				      pr_name(from->sin_addr),
				      ntohs(rap->icmp_lifetime));

		/* Check that at least one router address is a neighboor
		 * on the arriving link.
		 */
		for (i = 0; (unsigned)i < rap->icmp_num_addrs; i++) {
			struct in_addr ina;
			ap = (struct icmp_ra_addr *)
				ALLIGN(buf + hlen + 8 +
				       i * rap->icmp_wpa * 4);
			ina.s_addr = ap->ira_addr;
			if (verbose)
				logtrace("\taddress %s, preference 0x%x\n",
					      pr_name(ina),
					      (unsigned int)ntohl(ap->ira_preference));
			if (is_directly_connected(ina))
				record_router(ina,
					      ntohl(ap->ira_preference),
					      ntohs(rap->icmp_lifetime));
		}
		nreceived++;
		if (!forever) {
			do_fork();
			forever = 1;
/*
 * The next line was added so that the alarm is set for the new procces
 * Fraser Gardiner Sun Microsystems Australia
 */
			(void) alarm(TIMER_INTERVAL);
		}
		break;
	}

#ifdef RDISC_SERVER
	case ICMP_ROUTER_SOLICITATION:
	{
		struct sockaddr_in sin;

		if (!responder)
			break;

		/* TBD verify that the link is multicast or broadcast */
		/* XXX Find out the link it came in over? */

		if (in_cksum((unsigned short *)ALLIGN(buf+hlen), cc)) {
			if (verbose)
				logtrace("ICMP %s from %s: Bad checksum\n",
					      pr_type((int)icp->type),
					      pr_name(from->sin_addr));
			return;
		}
		if (icp->code != 0) {
			if (verbose)
				logtrace("ICMP %s from %s: Code = %d\n",
					      pr_type((int)icp->type),
					      pr_name(from->sin_addr),
					      icp->code);
			return;
		}

		if (cc < ICMP_MINLEN) {
			if (verbose)
				logtrace("ICMP %s from %s: Too short %d, %d\n",
					      pr_type((int)icp->type),
					      pr_name(from->sin_addr),
					      cc,
					      ICMP_MINLEN);
			return;
		}

		if (verbose)
			logtrace("ICMP %s from %s\n",
				      pr_type((int)icp->type),
				      pr_name(from->sin_addr));

		/* Check that ip_src is either a neighboor
		 * on the arriving link or 0.
		 */
		sin.sin_family = AF_INET;
		if (ip->saddr == 0) {
			/* If it was sent to the broadcast address we respond
			 * to the broadcast address.
			 */
			if (IN_CLASSD(ntohl(ip->daddr)))
				sin.sin_addr.s_addr = htonl(0xe0000001);
			else
				sin.sin_addr.s_addr = INADDR_BROADCAST;
			/* Restart the timer when we broadcast */
			left_until_advertise = min_adv_int +
				((max_adv_int - min_adv_int)
				 * (random() % 1000)/1000);
		} else {
			sin.sin_addr.s_addr = ip->saddr;
			if (!is_directly_connected(sin.sin_addr)) {
				if (verbose)
					logtrace("ICMP %s from %s: source not directly connected\n",
						      pr_type((int)icp->type),
						      pr_name(from->sin_addr));
				break;
			}
		}
		nreceived++;
		ntransmitted++;
		advertise(&sin, lifetime);
		break;
	}
#endif
	}
}


/*
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

unsigned short in_cksum(unsigned short *addr, int len)
{
	register int nleft = len;
	register unsigned short *w = addr;
	register unsigned short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while( nleft > 1 )  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if( nleft == 1 )
		sum += ODDBYTE(*(unsigned char *)w);	/* le16toh() may be unavailable on old systems */

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}

/*
 *			F I N I S H
 *
 * Print out statistics, and give up.
 * Heavily buffered STDIO is used here, so that all the statistics
 * will be written with 1 sys-write call.  This is nice when more
 * than one copy of the program is running on a terminal;  it prevents
 * the statistics output from becomming intermingled.
 */
void
finish()
{
#ifdef RDISC_SERVER
	if (responder) {
		/* Send out a packet with a preference so that all
		 * hosts will know that we are dead.
		 *
		 * Wrong comment, wrong code.
		 *	ttl must be set to 0 instead. --ANK
		 */
		logerr("terminated\n");
		ntransmitted++;
		advertise(&whereto, 0);
	}
#endif
	logtrace("\n----%s rdisc Statistics----\n", sendaddress );
	logtrace("%d packets transmitted, ", ntransmitted );
	logtrace("%d packets received, ", nreceived );
	logtrace("\n");
	(void) fflush(stdout);
	exit(0);
}

void
graceful_finish()
{
	discard_table();
	finish();
	exit(0);
}


/* From libc/rpc/pmap_rmt.c */

int
sendbcast(int s, char *packet, int packetlen)
{
	int i, cc;

	for (i = 0; i < num_interfaces; i++) {
		if ((interfaces[i].flags & (IFF_BROADCAST|IFF_POINTOPOINT)) == 0)
			continue;
		cc = sendbcastif(s, packet, packetlen, &interfaces[i]);
		if (cc!= packetlen) {
			return (cc);
		}
	}
	return (packetlen);
}

int
sendbcastif(int s, char *packet, int packetlen, struct interface *ifp)
{
	int on;
	int cc;
	struct sockaddr_in baddr;

	baddr.sin_family = AF_INET;
	baddr.sin_addr = ifp->bcastaddr;
	if (debug)
		logdebug("Broadcast to %s\n",
			 pr_name(baddr.sin_addr));
	on = 1;
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on));
	cc = sendto(s, packet, packetlen, 0,
		    (struct sockaddr *)&baddr, sizeof (struct sockaddr));
	if (cc!= packetlen) {
		logperror("sendbcast: sendto");
		logerr("Cannot send broadcast packet to %s\n",
		       pr_name(baddr.sin_addr));
	}
	on = 0;
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&on, sizeof(on));
	return (cc);
}

int
sendmcast(int s, char *packet, int packetlen, struct sockaddr_in *sin)
{
	int i, cc;

	for (i = 0; i < num_interfaces; i++) {
		if ((interfaces[i].flags & (IFF_BROADCAST|IFF_POINTOPOINT|IFF_MULTICAST)) == 0)
			continue;
		cc = sendmcastif(s, packet, packetlen, sin, &interfaces[i]);
		if (cc!= packetlen) {
			return (cc);
		}
	}
	return (packetlen);
}

int
sendmcastif(int s, char *packet, int packetlen,	struct sockaddr_in *sin,
	    struct interface *ifp)
{
	int cc;
	struct ip_mreqn mreq;

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_ifindex = ifp->ifindex;
	mreq.imr_address = ifp->localaddr;
	if (debug)
		logdebug("Multicast to interface %s, %s\n",
			 ifp->name,
			 pr_name(mreq.imr_address));
	if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
		       (char *)&mreq,
		       sizeof(mreq)) < 0) {
		logperror("setsockopt (IP_MULTICAST_IF)");
		logerr("Cannot send multicast packet over interface %s, %s\n",
		       ifp->name,
		       pr_name(mreq.imr_address));
		return (-1);
	}
	cc = sendto(s, packet, packetlen, 0,
		    (struct sockaddr *)sin, sizeof (struct sockaddr));
	if (cc!= packetlen) {
		logperror("sendmcast: sendto");
		logerr("Cannot send multicast packet over interface %s, %s\n",
		       ifp->name, pr_name(mreq.imr_address));
	}
	return (cc);
}

void
init()
{
	initifs();
#ifdef RDISC_SERVER
	{
		int i;
		for (i = 0; i < interfaces_size; i++)
			interfaces[i].preference = preference;
	}
#endif
}

void
initifs()
{
	int	sock;
	struct ifconf ifc;
	struct ifreq ifreq, *ifr;
	struct sockaddr_in *sin;
	int n, i;
	char *buf;
	int numifs;
	unsigned bufsize;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		logperror("initifs: socket");
		return;
	}
#ifdef SIOCGIFNUM
	if (ioctl(sock, SIOCGIFNUM, (char *)&numifs) < 0) {
		numifs = MAXIFS;
	}
#else
	numifs = MAXIFS;
#endif
	bufsize = numifs * sizeof(struct ifreq);
	buf = (char *)malloc(bufsize);
	if (buf == NULL) {
		logerr("out of memory\n");
		(void) close(sock);
		return;
	}
	if (interfaces != NULL)
		(void) free(interfaces);
	interfaces = (struct interface *)ALLIGN(malloc(numifs *
					sizeof(struct interface)));
	if (interfaces == NULL) {
		logerr("out of memory\n");
		(void) close(sock);
		(void) free(buf);
		return;
	}
	interfaces_size = numifs;

	ifc.ifc_len = bufsize;
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, (char *)&ifc) < 0) {
		logperror("initifs: ioctl (get interface configuration)");
		(void) close(sock);
		(void) free(buf);
		return;
	}
	ifr = ifc.ifc_req;
	for (i = 0, n = ifc.ifc_len/sizeof (struct ifreq); n > 0; n--, ifr++) {
		ifreq = *ifr;
		if (strlen(ifreq.ifr_name) >= IFNAMSIZ)
			continue;
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
			logperror("initifs: ioctl (get interface flags)");
			continue;
		}
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;
		if ((ifreq.ifr_flags & IFF_UP) == 0)
			continue;
		if (ifreq.ifr_flags & IFF_LOOPBACK)
			continue;
		if ((ifreq.ifr_flags & (IFF_MULTICAST|IFF_BROADCAST|IFF_POINTOPOINT)) == 0)
			continue;
		strncpy(interfaces[i].name, ifr->ifr_name, IFNAMSIZ-1);

		sin = (struct sockaddr_in *)ALLIGN(&ifr->ifr_addr);
		interfaces[i].localaddr = sin->sin_addr;
		interfaces[i].flags = ifreq.ifr_flags;
		interfaces[i].netmask.s_addr = (__u32)0xffffffff;
		if (ioctl(sock, SIOCGIFINDEX, (char *)&ifreq) < 0) {
			logperror("initifs: ioctl (get ifindex)");
			continue;
		}
		interfaces[i].ifindex = ifreq.ifr_ifindex;
		if (ifreq.ifr_flags & IFF_POINTOPOINT) {
			if (ioctl(sock, SIOCGIFDSTADDR, (char *)&ifreq) < 0) {
				logperror("initifs: ioctl (get destination addr)");
				continue;
			}
			sin = (struct sockaddr_in *)ALLIGN(&ifreq.ifr_addr);
			/* A pt-pt link is identified by the remote address */
			interfaces[i].address = sin->sin_addr;
			interfaces[i].remoteaddr = sin->sin_addr;
			/* Simulate broadcast for pt-pt */
			interfaces[i].bcastaddr = sin->sin_addr;
			interfaces[i].flags |= IFF_BROADCAST;
		} else {
			/* Non pt-pt links are identified by the local address */
			interfaces[i].address = interfaces[i].localaddr;
			interfaces[i].remoteaddr = interfaces[i].address;
			if (ioctl(sock, SIOCGIFNETMASK, (char *)&ifreq) < 0) {
				logperror("initifs: ioctl (get netmask)");
				continue;
			}
			sin = (struct sockaddr_in *)ALLIGN(&ifreq.ifr_addr);
			interfaces[i].netmask = sin->sin_addr;
			if (ifreq.ifr_flags & IFF_BROADCAST) {
				if (ioctl(sock, SIOCGIFBRDADDR, (char *)&ifreq) < 0) {
					logperror("initifs: ioctl (get broadcast address)");
					continue;
				}
				sin = (struct sockaddr_in *)ALLIGN(&ifreq.ifr_addr);
				interfaces[i].bcastaddr = sin->sin_addr;
			}
		}
#ifdef notdef
		if (debug)
			logdebug("Found interface %s, flags 0x%x\n",
				 pr_name(interfaces[i].localaddr),
				 interfaces[i].flags);
#endif
		i++;
	}
	num_interfaces = i;
#ifdef notdef
	if (debug)
		logdebug("Found %d interfaces\n", num_interfaces);
#endif
	(void) close(sock);
	(void) free(buf);
}

int
join(int sock, struct sockaddr_in *sin)
{
	int i, j;
	struct ip_mreqn mreq;
	int joined[num_interfaces];

	memset(joined, 0, sizeof(joined));

	if (isbroadcast(sin))
		return (0);

	mreq.imr_multiaddr = sin->sin_addr;
	for (i = 0; i < num_interfaces; i++) {
		for (j = 0; j < i; j++) {
			if (joined[j] == interfaces[i].ifindex)
				break;
		}
		if (j != i)
			continue;

		mreq.imr_ifindex = interfaces[i].ifindex;
		mreq.imr_address.s_addr = 0;

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			       (char *)&mreq, sizeof(mreq)) < 0) {
			logperror("setsockopt (IP_ADD_MEMBERSHIP)");
			return (-1);
		}

		joined[i] = interfaces[i].ifindex;
	}
	return (0);
}

int support_multicast()
{
	int sock;
	unsigned char ttl = 1;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		logperror("support_multicast: socket");
		return (0);
	}

	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL,
		       (char *)&ttl, sizeof(ttl)) < 0) {
		(void) close(sock);
		return (0);
	}
	(void) close(sock);
	return (1);
}

int
is_directly_connected(struct in_addr in)
{
	int i;

	for (i = 0; i < num_interfaces; i++) {
		/* Check that the subnetwork numbers match */

		if ((in.s_addr & interfaces[i].netmask.s_addr ) ==
		    (interfaces[i].remoteaddr.s_addr & interfaces[i].netmask.s_addr))
			return (1);
	}
	return (0);
}

/*
 * TABLES
 */
struct table {
	struct in_addr	router;
	int		preference;
	int		remaining_time;
	int		in_kernel;
	struct table	*next;
};

struct table *table;

struct table *
find_router(struct in_addr addr)
{
	struct table *tp;

	tp = table;
	while (tp) {
		if (tp->router.s_addr == addr.s_addr)
			return (tp);
		tp = tp->next;
	}
	return (NULL);
}

int max_preference(void)
{
	struct table *tp;
	int max = (int)INELIGIBLE_PREF;

	tp = table;
	while (tp) {
		if (tp->preference > max)
			max = tp->preference;
		tp = tp->next;
	}
	return (max);
}


/* Note: this might leave the kernel with no default route for a short time. */
void
age_table(int time)
{
	struct table **tpp, *tp;
	int recalculate_max = 0;
	int max = max_preference();

	tpp = &table;
	while (*tpp != NULL) {
		tp = *tpp;
		tp->remaining_time -= time;
		if (tp->remaining_time <= 0) {
			*tpp = tp->next;
			if (tp->in_kernel)
				del_route(tp->router);
			if (best_preference &&
			    tp->preference == max)
				recalculate_max++;
			free((char *)tp);
		} else {
			tpp = &tp->next;
		}
	}
	if (recalculate_max) {
		int max = max_preference();

		if (max != INELIGIBLE_PREF) {
			tp = table;
			while (tp) {
				if (tp->preference == max && !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
}

void discard_table(void)
{
	struct table **tpp, *tp;

	tpp = &table;
	while (*tpp != NULL) {
		tp = *tpp;
		*tpp = tp->next;
		if (tp->in_kernel)
			del_route(tp->router);
		free((char *)tp);
	}
}


void
record_router(struct in_addr router, int preference, int ttl)
{
	struct table *tp;
	int old_max = max_preference();
	int changed_up = 0;	/* max preference could have increased */
	int changed_down = 0;	/* max preference could have decreased */

	if (ttl < 4)
		preference = INELIGIBLE_PREF;

	if (debug)
		logdebug("Recording %s, ttl %d, preference 0x%x\n",
			 pr_name(router),
			 ttl,
			 preference);
	tp = find_router(router);
	if (tp) {
		if (tp->preference > preference &&
		    tp->preference == old_max)
			changed_down++;
		else if (preference > tp->preference)
			changed_up++;
		tp->preference = preference;
		tp->remaining_time = ttl;
	} else {
		if (preference > old_max)
			changed_up++;
		tp = (struct table *)ALLIGN(malloc(sizeof(struct table)));
		if (tp == NULL) {
			logerr("Out of memory\n");
			return;
		}
		tp->router = router;
		tp->preference = preference;
		tp->remaining_time = ttl;
		tp->in_kernel = 0;
		tp->next = table;
		table = tp;
	}
	if (!tp->in_kernel &&
	    (!best_preference || tp->preference == max_preference()) &&
	    tp->preference != INELIGIBLE_PREF) {
		add_route(tp->router);
		tp->in_kernel++;
	}
	if (tp->preference == INELIGIBLE_PREF && tp->in_kernel) {
		del_route(tp->router);
		tp->in_kernel = 0;
	}
	if (best_preference && changed_down) {
		/* Check if we should add routes */
		int new_max = max_preference();
		if (new_max != INELIGIBLE_PREF) {
			tp = table;
			while (tp) {
				if (tp->preference == new_max &&
				    !tp->in_kernel) {
					add_route(tp->router);
					tp->in_kernel++;
				}
				tp = tp->next;
			}
		}
	}
	if (best_preference && (changed_up || changed_down)) {
		/* Check if we should remove routes already in the kernel */
		int new_max = max_preference();
		tp = table;
		while (tp) {
			if (tp->preference < new_max && tp->in_kernel) {
				del_route(tp->router);
				tp->in_kernel = 0;
			}
			tp = tp->next;
		}
	}
}

void
add_route(struct in_addr addr)
{
	if (debug)
		logdebug("Add default route to %s\n", pr_name(addr));
	rtioctl(addr, SIOCADDRT);
}

void
del_route(struct in_addr addr)
{
	if (debug)
		logdebug("Delete default route to %s\n", pr_name(addr));
	rtioctl(addr, SIOCDELRT);
}

void
rtioctl(struct in_addr addr, int op)
{
	int sock;
	struct rtentry rt;
	struct sockaddr_in *sin;

	memset((char *)&rt, 0, sizeof(struct rtentry));
	rt.rt_dst.sa_family = AF_INET;
	rt.rt_gateway.sa_family = AF_INET;
	rt.rt_genmask.sa_family = AF_INET;
	sin = (struct sockaddr_in *)ALLIGN(&rt.rt_gateway);
	sin->sin_addr = addr;
	rt.rt_flags = RTF_UP | RTF_GATEWAY;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		logperror("rtioctl: socket");
		return;
	}
	if (ioctl(sock, op, (char *)&rt) < 0) {
		if (!(op == SIOCADDRT && errno == EEXIST))
			logperror("ioctl (add/delete route)");
	}
	(void) close(sock);
}

/*
 * LOGGER
 */

void initlog(void)
{
	logging++;
	openlog("in.rdiscd", LOG_PID | LOG_CONS, LOG_DAEMON);
}


void
logperror(char *str)
{
	if (logging)
		syslog(LOG_ERR, "%s: %m", str);
	else
		(void) fprintf(stderr, "%s: %s\n", str, strerror(errno));
}
