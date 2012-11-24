/* $USAGI: ninfod.h,v 1.20 2002-12-19 15:51:16 yoshfuji Exp $ */
/*
 * Copyright (C) 2002 USAGI/WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Author:
 * 	YOSHIFUJI Hideaki <yoshfuji@linux-ipv6.org>
 */

/* definitions */
#define NINFOD			"ninfod"
#define NINFOD_PIDFILE		"/var/run/ninfod.pid"

#define	MAX_ANYCAST_DELAY_TIME	1000000.0	/* 1 sec */

#define MAX_DNSLABEL_SIZE	63
#define MAX_DNSNAME_SIZE	255
#define MAX_QUERY_SIZE		(sizeof(struct icmp6_nodeinfo)+MAX_DNSNAME_SIZE+2)
#define MAX_REPLY_SIZE		1280-sizeof(struct ip6_hdr)

#define MAX_SUPTYPES		32

#define CHECKANDFILL_ARGS	struct packetcontext *p,\
				char *subject, size_t subjlen,	\
				unsigned int flags,		\
				unsigned int *subj_if,		\
				int reply
#define INIT_ARGS		\
				int forced

struct packetcontext {
	/* socket */
	int sock;

	/* query info */
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct in6_pktinfo pktinfo;
	char query[MAX_QUERY_SIZE];
	int querylen;

	/* reply info */
	struct icmp6_nodeinfo reply;	/* common */
	char *replydata;		/* data */
	int replydatalen;

	unsigned int delay;		/* (random) delay */
};

/* variables */
extern int opt_v;		/* ninfod.c */
extern int daemonized;		/* ninfod.c */
extern int sock;		/* ninfod.c */
extern int initialized;		/* ninfod_core.c */

/* ninfod.c* */
int ni_recv(struct packetcontext *p);
int ni_send(struct packetcontext *p);

/* ninfod_core.c */
#if ENABLE_DEBUG
void stderrlog(int priority, char *format, ...);
# define DEBUG(pri, fmt, args...)	do {									\
						int saved_errno = errno;					\
						if (opt_v || pri != LOG_DEBUG) {				\
							if (daemonized) {					\
								syslog(pri, fmt, ## args);			\
							} else {						\
								stderrlog(pri, fmt, ## args);			\
							}							\
						}								\
						errno = saved_errno;						\
					} while(0)
#else
# define DEBUG(pri, fmt, args...)	do { ; } while(0)
#endif

#define ni_malloc(size)	({										\
				size_t _size = (size);							\
				void *p = malloc(_size);						\
				DEBUG(LOG_DEBUG, "%s(): malloc(%zu) = %p\n", __func__, _size, p);	\
				p;									\
			})
#define ni_free(p)	({										\
				void *_p = (p);								\
				int saved_errno = errno;						\
				DEBUG(LOG_DEBUG, "%s(): free(%p)\n", __func__, _p);			\
				free(_p);								\
				errno = saved_errno;							\
			})

void init_core(int forced);
int pr_nodeinfo(struct packetcontext *p);

int pr_nodeinfo_unknown(CHECKANDFILL_ARGS);
int pr_nodeinfo_refused(CHECKANDFILL_ARGS);
int pr_nodeinfo_noop(CHECKANDFILL_ARGS);
void init_nodeinfo_suptypes(INIT_ARGS);
int pr_nodeinfo_suptypes(CHECKANDFILL_ARGS);

/* ninfod_addrs.c */
void init_nodeinfo_ipv6addr(INIT_ARGS);
int pr_nodeinfo_ipv6addr(CHECKANDFILL_ARGS);
void init_nodeinfo_ipv4addr(INIT_ARGS);
int pr_nodeinfo_ipv4addr(CHECKANDFILL_ARGS);

/* ninfod_name.c */
int check_nigroup(const struct in6_addr *addr);
void init_nodeinfo_nodename(INIT_ARGS);
int pr_nodeinfo_nodename(CHECKANDFILL_ARGS);

