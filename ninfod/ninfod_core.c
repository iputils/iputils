/* $USAGI: ninfod_core.c,v 1.29 2003-07-16 09:49:01 yoshfuji Exp $ */
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if STDC_HEADERS
# include <stdio.h>
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#if ENABLE_THREADS && HAVE_PTHREAD_H
# include <pthread.h>
#endif
#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#if TIME_WITH_SYS_TIME   
# include <sys/time.h>  
# include <time.h>
#else
# if HAVE_SYS_TIME_H     
#  include <sys/time.h>
# else                
#  include <time.h>
# endif                  
#endif                   

#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if HAVE_NETINET_ICMP6_H
# include <netinet/icmp6.h>
#endif
#ifndef HAVE_STRUCT_ICMP6_NODEINFO
# include "icmp6_nodeinfo.h"
#endif

#if HAVE_NETDB_H
# include <netdb.h>
#endif
#include <errno.h>

#if HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "ninfod.h"

#ifndef offsetof
# define offsetof(aggregate,member)	((size_t)&((aggregate *)0)->member)
#endif

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof(a[0]))

/* ---------- */
/* ID */
static char *RCSID __attribute__ ((unused)) = "$USAGI: ninfod_core.c,v 1.29 2003-07-16 09:49:01 yoshfuji Exp $";

/* Variables */
int initialized = 0;

#if ENABLE_THREADS && HAVE_LIBPTHREAD
pthread_attr_t pattr;
#endif

static uint32_t suptypes[(MAX_SUPTYPES+31)>>5];
static size_t suptypes_len;

/* ---------- */
struct subjinfo {
	uint8_t	code;
	char	*name;
	int	(*checksubj)(CHECKANDFILL_ARGS);
	int	(*init)(INIT_ARGS);
};

static struct subjinfo subjinfo_table [] = {
	[ICMP6_NI_SUBJ_IPV6] = {
		.code = ICMP6_NI_SUBJ_IPV6,
		.name = "IPv6",
		//.init = init_nodeinfo_ipv6addr,
		.checksubj = pr_nodeinfo_ipv6addr,
	},
	[ICMP6_NI_SUBJ_FQDN] = {
		.code = ICMP6_NI_SUBJ_FQDN,
		.name = "FQDN",
		//.init = init_nodeinfo_nodename,
		.checksubj = pr_nodeinfo_nodename,
	},
	[ICMP6_NI_SUBJ_IPV4] = {
		.code = ICMP6_NI_SUBJ_IPV4,
		.name = "IPv4",
		//.init = init_nodeinfo_ipv4addr,
		.checksubj = pr_nodeinfo_ipv4addr,
	},
};

static struct subjinfo subjinfo_null = {
	.name = "null",
	.checksubj = pr_nodeinfo_noop,
};

static __inline__ struct subjinfo *subjinfo_lookup(int code)
{
	if (code >= ARRAY_SIZE(subjinfo_table))
		return NULL;
	if (subjinfo_table[code].name == NULL)
		return NULL;
	return &subjinfo_table[code];
}

/* ---------- */
#define QTYPEINFO_F_RATELIMIT	0x1

struct qtypeinfo {
	uint16_t qtype;
	char	*name;
	int	(*getreply)(CHECKANDFILL_ARGS);
	void	(*init)(INIT_ARGS);
	int	flags;
};

static struct qtypeinfo qtypeinfo_table[] = {
	[NI_QTYPE_NOOP]		= {
		.qtype = NI_QTYPE_NOOP,
		.name = "NOOP",
		.getreply = pr_nodeinfo_noop,
	},
#if ENABLE_SUPTYPES
	[NI_QTYPE_SUPTYPES]	= {
		.qtype = NI_QTYPE_SUPTYPES,
		.name = "SupTypes",
		.getreply = pr_nodeinfo_suptypes,
		.init = init_nodeinfo_suptypes,
	},
#endif
	[NI_QTYPE_DNSNAME]	= {
		.qtype = NI_QTYPE_DNSNAME,
		.name = "DnsName",
		.getreply = pr_nodeinfo_nodename,
		.init = init_nodeinfo_nodename,
	},
	[NI_QTYPE_NODEADDR]	= {
		.qtype = NI_QTYPE_NODEADDR,
		.name = "NodeAddr",
		.getreply = pr_nodeinfo_ipv6addr,
		.init = init_nodeinfo_ipv6addr,
	},
	[NI_QTYPE_IPV4ADDR]	= {
		.qtype = NI_QTYPE_IPV4ADDR,
		.name = "IPv4Addr",
		.getreply = pr_nodeinfo_ipv4addr,
		.init = init_nodeinfo_ipv4addr,
	},
};

static struct qtypeinfo qtypeinfo_unknown = {
	.name = "unknown",
	.getreply = pr_nodeinfo_unknown,
	.flags = QTYPEINFO_F_RATELIMIT,
};

static struct qtypeinfo qtypeinfo_refused = {
	.name = "refused",
	.getreply = pr_nodeinfo_refused,
	.flags = QTYPEINFO_F_RATELIMIT,
};

static __inline__ struct qtypeinfo *qtypeinfo_lookup(int qtype)
{
	if (qtype >= ARRAY_SIZE(qtypeinfo_table))
		return &qtypeinfo_unknown;
	if (qtypeinfo_table[qtype].name == NULL)
		return &qtypeinfo_unknown;
	return &qtypeinfo_table[qtype];
}

/* ---------- */
/* noop */
int pr_nodeinfo_noop(CHECKANDFILL_ARGS)
{
	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	if (subjlen) {
		DEBUG(LOG_WARNING,
		      "%s(): invalid subject length(%zu)\n",
		      __func__, subjlen);
		return 1;
	}

	if (reply) {
		p->reply.ni_type = ICMP6_NI_REPLY;
		p->reply.ni_code = ICMP6_NI_SUCCESS;
		p->reply.ni_cksum = 0;
		p->reply.ni_qtype = htons(NI_QTYPE_NOOP);
		p->reply.ni_flags = flags;
	}

	if (subj_if)
		*subj_if = 0;

	return 0;
}

#if ENABLE_SUPTYPES
/* suptypes */
int pr_nodeinfo_suptypes(CHECKANDFILL_ARGS)
{
	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	if (subjlen) {
		DEBUG(LOG_WARNING, "%s(): invalid subject length(%zu)\n",
		      __func__, subjlen);
		return 1;
	}

	if (reply) {
		p->reply.ni_type = ICMP6_NI_REPLY;
		p->reply.ni_code = ICMP6_NI_SUCCESS;
		p->reply.ni_cksum = 0;
		p->reply.ni_qtype = htons(NI_QTYPE_SUPTYPES);
		p->reply.ni_flags = flags&~NI_SUPTYPE_FLAG_COMPRESS;
		
		p->replydatalen = suptypes_len<<2;
		p->replydata = ni_malloc(p->replydatalen);
		if (p->replydata == NULL) {
			p->replydatalen = -1;
			return -1;	/*XXX*/
		}

		memcpy(p->replydata, suptypes, p->replydatalen);
	}
	return 0;
}

void init_nodeinfo_suptypes(INIT_ARGS)
{
	size_t w, b;
	int i;

	if (!forced && initialized)
		return;

	memset(suptypes, 0, sizeof(suptypes));
	suptypes_len = 0;

	for (i=0; i < ARRAY_SIZE(qtypeinfo_table); i++) {
		unsigned short qtype;

		if (qtypeinfo_table[i].name == NULL)
			continue;
		qtype = qtypeinfo_table[i].qtype;
		w = qtype>>5;
		b = qtype&0x1f;
		if (w >= ARRAY_SIZE(suptypes)) {
			/* This is programming error. */
			DEBUG(LOG_ERR, "Warning: Too Large Supported Types\n");
			exit(1);
		}
		suptypes[w] |= htonl(1<<b);

		if (suptypes_len < w)
			suptypes_len = w;
	}
	suptypes_len++;
}
#endif

/* ---------- */
/* unknown qtype response */
int pr_nodeinfo_unknown(CHECKANDFILL_ARGS)
{
	if (!reply)
		return -1;	/*???*/

	p->reply.ni_type = ICMP6_NI_REPLY;
	p->reply.ni_code = ICMP6_NI_UNKNOWN;
	p->reply.ni_cksum = 0;
	//p->reply.ni_qtype = 0;
	p->reply.ni_flags = flags;

	p->replydata = NULL;
	p->replydatalen = 0;

	return 0;
}

/* refused response */
int pr_nodeinfo_refused(CHECKANDFILL_ARGS)
{
	if (!reply)
		return -1;	/*???*/

	p->reply.ni_type = ICMP6_NI_REPLY;
	p->reply.ni_code = ICMP6_NI_REFUSED;
	p->reply.ni_cksum = 0;
	//p->reply.ni_qtype = 0;
	p->reply.ni_flags = flags;

	p->replydata = NULL;
	p->replydatalen = 0;

	return 0;
}

/* ---------- */
/* Policy */
static int ni_policy(struct packetcontext *p)
{
	const struct in6_addr *saddr = &((const struct sockaddr_in6 *)&p->addr)->sin6_addr;

	/*
	 * >0: reply
	 *  0: refused
	 * <0: discard
	 */

	/* Default policy is to refuse queries from
	 * non-local addresses; loopback, link-local or
	 * site-local are okay
	 */
	if (!(IN6_IS_ADDR_LINKLOCAL(saddr) ||
	      IN6_IS_ADDR_SITELOCAL(saddr) ||
	      IN6_IS_ADDR_LOOPBACK(saddr)))
		return 0;
	return 1;
}

/* ---------- */
void init_core(int forced)
{
	int i;

	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	if (!initialized || forced) {
		struct timeval tv;
		unsigned int seed = 0;
		pid_t pid;

		if (gettimeofday(&tv, NULL) < 0) {
			DEBUG(LOG_WARNING, "%s(): failed to gettimeofday()\n", __func__);
		} else {
			seed = (tv.tv_usec & 0xffffffff);
		}

		pid = getpid();
		seed ^= (((unsigned long)pid) & 0xffffffff);

		srand(seed);

#if ENABLE_THREADS && HAVE_LIBPTHREAD
		if (initialized)
			pthread_attr_destroy(&pattr);

		pthread_attr_init(&pattr);
		pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_DETACHED);
#endif
	}

	for (i=0; i < ARRAY_SIZE(subjinfo_table); i++) {
		if (subjinfo_table[i].name == NULL)
			continue;
		if (subjinfo_table[i].init)
			subjinfo_table[i].init(forced);
	}

	for (i=0; i < ARRAY_SIZE(qtypeinfo_table); i++) {
		if (qtypeinfo_table[i].name == NULL)
			continue;
		if (qtypeinfo_table[i].init)
			qtypeinfo_table[i].init(forced);
	}

	initialized = 1;

	return;
}

#if ENABLE_THREADS && HAVE_LIBPTHREAD
static void *ni_send_thread(void *data)
{
	int ret;
	DEBUG(LOG_DEBUG, "%s(): thread=%ld\n", __func__, pthread_self());
	ret = ni_send(data);
	DEBUG(LOG_DEBUG, "%s(): thread=%ld => %d\n", __func__, pthread_self(), ret);
	return NULL;
}
#else
static int ni_send_fork(struct packetcontext *p)
{
	pid_t child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		pid_t grandchild = fork();
		if (grandchild < 0)
			exit(1);
		if (grandchild == 0) {
			int ret;
			DEBUG(LOG_DEBUG, "%s(): worker=%d\n",
			      __func__, getpid());
			ret = ni_send(p);
			DEBUG(LOG_DEBUG, "%s(): worker=%d => %d\n",
			      __func__, getpid(), ret);
			exit(ret > 0 ? 1 : 0);
		}
		ni_free(p->replydata);
		ni_free(p);
		exit(0);
	} else {
		waitpid(child, NULL, 0);
		ni_free(p->replydata);
		ni_free(p);
	}
	return 0;
}
#endif

static int ni_ratelimit(void)
{
	static struct timeval last;
	struct timeval tv, sub;

	if (gettimeofday(&tv, NULL) < 0) {
		DEBUG(LOG_WARNING, "%s(): gettimeofday(): %s\n",
		      __func__, strerror(errno));
		return -1;
	}

	if (!timerisset(&last)) {
		last = tv;
		return 0;
	}

	timersub(&tv, &last, &sub);

	if (sub.tv_sec < 1)
		return 1;

	last = tv;
	return 0;
}

int pr_nodeinfo(struct packetcontext *p)
{
	struct icmp6_nodeinfo *query = (struct icmp6_nodeinfo *)p->query;

	char *subject = (char *)(query + 1);
	size_t subjlen;
	struct subjinfo *subjinfo;
	struct qtypeinfo *qtypeinfo;
	int replyonsubjcheck = 0;
	unsigned int subj_if;
#if ENABLE_DEBUG
	char printbuf[128];
	int i;
	char *cp;
#endif
#if ENABLE_THREADS && HAVE_PTHREAD_H
	pthread_t thread;
#endif
	int rc;

	/* Step 0: Check destination address
	 *		discard non-linklocal multicast
	 *		discard non-nigroup multicast address(?)
	 */
	if (IN6_IS_ADDR_MULTICAST(&p->pktinfo.ipi6_addr)) {
		if (!IN6_IS_ADDR_MC_LINKLOCAL(&p->pktinfo.ipi6_addr)) {
			DEBUG(LOG_WARNING,
			      "Destination is non-link-local multicast address.\n");
			ni_free(p);
			return -1;
		}
#if 0
		/* Do not discard NI Queries to multicast address
		 * other than its own NI Group Address(es) by default.
		 */
		if (!check_nigroup(&p->pktinfo.ipi6_addr)) {
			DEBUG(LOG_WARNING,
			      "Destination is link-local multicast address other than "
			      "NI Group address.\n");
			ni_free(p);
			return -1;
		}
#endif
	}

	/* Step 1: Check length */
	if (p->querylen < sizeof(struct icmp6_nodeinfo)) {
		DEBUG(LOG_WARNING, "Query too short\n");
		ni_free(p);
		return -1;
	}

#if ENABLE_DEBUG
	cp = printbuf;
	for (i = 0; i < sizeof(query->icmp6_ni_nonce); i++) {
		cp += sprintf(cp, " %02x", query->icmp6_ni_nonce[i]);
	}
	DEBUG(LOG_DEBUG, "%s(): qtype=%d, flags=0x%04x, nonce[] = {%s }\n",
	      __func__,
	      ntohs(query->ni_qtype), ntohs(query->ni_flags), printbuf);
#endif

	subjlen = p->querylen - sizeof(struct icmp6_nodeinfo);

	/* Step 2: Check Subject Code */
	switch(htons(query->ni_qtype)) {
	case NI_QTYPE_NOOP:
	case NI_QTYPE_SUPTYPES:
		if (query->ni_code != ICMP6_NI_SUBJ_FQDN) {
			DEBUG(LOG_WARNING,
			      "%s(): invalid/unknown code %u\n",
			      __func__, query->ni_code);
			subjlen = 0;
		}
		subjinfo = &subjinfo_null;
		break;
	default:
		subjinfo = subjinfo_lookup(query->ni_code);
		if (!subjinfo) {
			DEBUG(LOG_WARNING,
			      "%s(): unknown code %u\n",
			      __func__, query->ni_code);
			ni_free(p);
			return -1;
		}
	}

	/* Step 3: Lookup Qtype */
	qtypeinfo = qtypeinfo_lookup(ntohs(query->ni_qtype));

	/* Step 4: Check Subject
	 *         (And fill reply if it is available now)
	 */
	if (qtypeinfo->getreply == subjinfo->checksubj)
		replyonsubjcheck = 1;

	if (subjinfo->checksubj(p,
				subject, subjlen,
				query->ni_flags,
				replyonsubjcheck ? NULL : &subj_if,
				replyonsubjcheck)) {
		if (p->replydatalen < 0) {
			DEBUG(LOG_WARNING,
			      "failed to make reply: %s\n",
			      strerror(errno));
		}
		ni_free(p);
		return -1;
	}

	/* XXX: Step 5: Check the policy */
	rc = ni_policy(p);
	if (rc <= 0) {
		ni_free(p->replydata);
		p->replydata = NULL;
		p->replydatalen = 0;
		if (rc < 0) {
			DEBUG(LOG_WARNING, "Ignored by policy.\n");
			ni_free(p);
			return -1;
		}
		DEBUG(LOG_WARNING, "Refused by policy.\n");
		replyonsubjcheck = 0;
		qtypeinfo = &qtypeinfo_refused;
	}

	/* Step 6: Fill the reply if not yet done */
	if (!replyonsubjcheck) {
		if (qtypeinfo->getreply(p,
					NULL, 0,
					query->ni_flags,
					&subj_if,
					1)) {
			if (p->replydatalen) {
				DEBUG(LOG_WARNING,
				      "failed to make reply: %s\n",
				      strerror(errno));
			}
			ni_free(p);
			return -1;
		}
	}

	/* Step 7: Rate Limit */
	if (qtypeinfo->flags&QTYPEINFO_F_RATELIMIT &&
	    ni_ratelimit()) {
		ni_free(p->replydata);
		ni_free(p);
		return -1;
	}

	/* Step 8: Fill Qtype / Nonce */
	p->reply.ni_qtype = query->ni_qtype;
	memcpy(p->reply.icmp6_ni_nonce, query->icmp6_ni_nonce, sizeof(p->reply.icmp6_ni_nonce));

	/* Step 9: Source address selection */
	if (IN6_IS_ADDR_MULTICAST(&p->pktinfo.ipi6_addr)) {
		/* if query was sent to multicast address,
		 * use source address selection in kernel.
		 * XXX: anycast?
		 */
		memset(&p->pktinfo.ipi6_addr, 0, sizeof(p->pktinfo.ipi6_addr));

	 	/* Random Delay between zero and MAX_ANYCAST_DELAY_TIME is
		 * required if query was sent to anycast or multicast address.
		 */
		p->delay = (int) (MAX_ANYCAST_DELAY_TIME*rand()/(RAND_MAX+1.0));
	} else {
		p->delay = 0;
	}

	/* Step 10: Send the reply
	 * XXX: with possible random delay */
#if ENABLE_THREADS && HAVE_LIBPTHREAD
	/* ni_send_thread() frees p */
	if (pthread_create(&thread, &pattr, ni_send_thread, p)) {
		ni_free(p->replydata);
		ni_free(p);
		return -1;
	}
#else
	/* ni_send_fork() frees p */
	if (ni_send_fork(p)) {
		ni_free(p->replydata);
		ni_free(p);
		return -1;
	}
#endif

	return 0;
}

