/* $USAGI: ninfod_addrs.c,v 1.18 2003-07-16 09:49:01 yoshfuji Exp $ */
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

#include <sys/socket.h>
#if HAVE_LINUX_RTNETLINK_H
#include <asm/types.h>
#include <linux/rtnetlink.h>
#endif

#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if HAVE_NETINET_IP6_H
# include <netinet/ip6.h>
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
#include "ni_ifaddrs.h"

#ifndef offsetof
# define offsetof(aggregate,member)	((size_t)&((aggregate *)0)->member)
#endif

/* ---------- */
/* ID */
static char *RCSID __attribute__ ((unused)) = "$USAGI: ninfod_addrs.c,v 1.18 2003-07-16 09:49:01 yoshfuji Exp $";

/* ---------- */
/* ipv6 address */
void init_nodeinfo_ipv6addr(INIT_ARGS)
{
	DEBUG(LOG_DEBUG, "%s()\n", __func__);
	return;
}

int filter_ipv6addr(const struct in6_addr *ifaddr, unsigned int flags)
{
	if (IN6_IS_ADDR_UNSPECIFIED(ifaddr) ||
	    IN6_IS_ADDR_LOOPBACK(ifaddr)) {
		return 1;
	} else if (IN6_IS_ADDR_V4COMPAT(ifaddr) ||
		   IN6_IS_ADDR_V4MAPPED(ifaddr)) {
		return !(flags & NI_NODEADDR_FLAG_COMPAT);
	} else if (IN6_IS_ADDR_LINKLOCAL(ifaddr)) {
		return !(flags & NI_NODEADDR_FLAG_LINKLOCAL);
	} else if (IN6_IS_ADDR_SITELOCAL(ifaddr)) {
		return !(flags & NI_NODEADDR_FLAG_SITELOCAL);
	}
	return !(flags & NI_NODEADDR_FLAG_GLOBAL);
}

int pr_nodeinfo_ipv6addr(CHECKANDFILL_ARGS)
{
	struct ni_ifaddrs *ifa0;
	unsigned int ifindex = 0;

	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	if (subject && subjlen != sizeof(struct in6_addr)) {
		DEBUG(LOG_INFO,
		      "%s(): invalid subject length %zu for IPv6 Address Subject\n",
		      __func__, subjlen);
		return 1;
	}
	if (ni_ifaddrs(&ifa0, AF_INET6))
		return -1;	/* failed to get addresses */

	/* pass 0: consider subject and determine subjected interface */
	if (subject) {
		struct ni_ifaddrs *ifa;

		for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
			if (!ifa->ifa_addr)
				continue;
			if (ifa->ifa_flags & (IFA_F_TENTATIVE|IFA_F_SECONDARY))
				continue;
			if (!ifindex && 
			    IN6_ARE_ADDR_EQUAL(&p->pktinfo.ipi6_addr,
					       (struct in6_addr *)subject)) {
				/*
				 * if subject is equal to destination
				 * address, receiving interface is
				 * the candidate subject interface.
				 */
				ifindex = p->pktinfo.ipi6_ifindex;
			}
			if (!IN6_IS_ADDR_LOOPBACK((struct in6_addr *)subject) &&
			    IN6_ARE_ADDR_EQUAL((struct in6_addr *)ifa->ifa_addr,
					       (struct in6_addr *)subject)) {
				/*
				 * address is assigned on some interface.
				 * if multiple interfaces have the same interface,
				 *  1) prefer receiving interface
				 *  2) use first found one
				 */
				if (!ifindex ||
				    (p->pktinfo.ipi6_ifindex == ifindex))
					ifindex = ifa->ifa_ifindex;
			}
		}
		if (!ifindex) {
			ni_freeifaddrs(ifa0);
			return 1;	/* subject not found */
		}
		if (subj_if)
			*subj_if = ifindex;
	} else {
		ifindex = subj_if ? *subj_if : 0;
		if (ifindex == 0)
			ifindex = p->pktinfo.ipi6_ifindex;
		if (ifindex == 0) {
			ni_freeifaddrs(ifa0);
			return 1;	/* XXX */
		}
	}

	if (reply) {
		struct ni_ifaddrs *ifa;
		unsigned int addrs0 = 0, paddrs0 = 0;
		unsigned int addrs, paddrs = 0, daddrs = 0;

		flags &= ~NI_NODEADDR_FLAG_TRUNCATE;	
	
		/* pass 1: count addresses and preferred addresses to be returned */
		for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
			if (!ifa->ifa_addr)
				continue;
			if (ifa->ifa_flags & (IFA_F_TENTATIVE|IFA_F_SECONDARY))
				continue;
			if (!(flags & NI_NODEADDR_FLAG_ALL) &&
			    ifa->ifa_ifindex != ifindex)
				continue;
			if (filter_ipv6addr((struct in6_addr *)ifa->ifa_addr, flags))
				continue;

			if (addrs0 + 1 >= ((MAX_REPLY_SIZE - sizeof(struct icmp6_nodeinfo)) / (sizeof(uint32_t) + sizeof(struct in6_addr)))) {
				flags |= ~NI_NODEADDR_FLAG_TRUNCATE;
				break;
			}

			addrs0++;
			if (!(ifa->ifa_flags & IFA_F_DEPRECATED))
				paddrs0++;
		}
		
		p->reply.ni_type = ICMP6_NI_REPLY;
		p->reply.ni_code = ICMP6_NI_SUCCESS;
		p->reply.ni_cksum = 0;
		p->reply.ni_qtype = htons(NI_QTYPE_NODEADDR);
		p->reply.ni_flags = flags&(NI_NODEADDR_FLAG_COMPAT|
					   NI_NODEADDR_FLAG_LINKLOCAL|
					   NI_NODEADDR_FLAG_SITELOCAL|
					   NI_NODEADDR_FLAG_GLOBAL);

		/* pass 2: store addresses */
		p->replydatalen = (sizeof(uint32_t)+sizeof(struct in6_addr)) * addrs0;
		p->replydata = p->replydatalen ? ni_malloc(p->replydatalen) : NULL;

		if (p->replydatalen && !p->replydata) {
			p->reply.ni_flags |= NI_NODEADDR_FLAG_TRUNCATE;
			addrs0 = paddrs0 = 0;
		}

		for (ifa = ifa0, addrs = 0; 
		     ifa && addrs < addrs0; 
		     ifa = ifa->ifa_next) {
			char *cp;
			uint32_t ttl;

			if (!ifa->ifa_addr)
				continue;
			if (ifa->ifa_flags & (IFA_F_TENTATIVE|IFA_F_SECONDARY))
				continue;
			if (!(flags & NI_NODEADDR_FLAG_ALL) &&
			    ((subj_if && *subj_if) ? (ifa->ifa_ifindex != *subj_if) :
						     (ifa->ifa_ifindex != p->pktinfo.ipi6_ifindex)))
				continue;
			if (filter_ipv6addr((struct in6_addr *)ifa->ifa_addr, flags))
				continue;

#if ENABLE_TTL
			if (ifa->ifa_cacheinfo) {
				ttl = ifa->ifa_cacheinfo->ifa_valid > 0x7fffffff ? 
				      htonl(0x7fffffff) : htonl(ifa->ifa_cacheinfo->ifa_valid);
			} else {
				ttl = (ifa->ifa_flags & IFA_F_PERMANENT) ? htonl(0x7fffffff) : 0;
			}
#else
			ttl = 0;
#endif

			cp = p->replydata +
			     (sizeof(uint32_t)+sizeof(struct in6_addr)) * (ifa->ifa_flags & IFA_F_DEPRECATED ? paddrs0+daddrs : paddrs);
			memcpy(cp, &ttl, sizeof(ttl));
			memcpy(cp + sizeof(ttl), ifa->ifa_addr, sizeof(struct in6_addr));

			addrs++;
			if (ifa->ifa_flags & IFA_F_DEPRECATED)
				daddrs++;
			else
				paddrs++;
		}
	}

	ni_freeifaddrs(ifa0);
	return 0;
}

/* ipv4 address */
void init_nodeinfo_ipv4addr(INIT_ARGS)
{
	DEBUG(LOG_DEBUG, "%s()\n", __func__);
	return;
}

int filter_ipv4addr(const struct in_addr *ifaddr, unsigned int flags)
{
	return 0;
}

int pr_nodeinfo_ipv4addr(CHECKANDFILL_ARGS)
{
	struct ni_ifaddrs *ifa0;
	unsigned int ifindex = 0;

	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	if (subject && subjlen != sizeof(struct in_addr)) {
		DEBUG(LOG_INFO,
		      "%s(): invalid subject length %zu for IPv4 Address Subject\n",
		      __func__, subjlen);
		return 1;
	}
	if (ni_ifaddrs(&ifa0, AF_INET))
		return -1;	/* failed to get addresses */

	/* pass 0: consider subject and determine subjected interface */
	if (subject) {
		struct ni_ifaddrs *ifa;

		for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
			if (!ifa->ifa_addr)
				continue;
			if (ifa->ifa_flags & (IFA_F_TENTATIVE|IFA_F_SECONDARY))
				continue;
			if ((((struct in_addr *)subject)->s_addr != htonl(INADDR_LOOPBACK)) &&
			    memcmp((struct in_addr *)ifa->ifa_addr,
				   (struct in_addr *)subject,
				   sizeof(struct in_addr)) == 0) {
				/*
				 * address is assigned on some interface.
				 * if multiple interfaces have the same interface,
				 *  1) prefer receiving interface
				 *  2) use first found one
				 */
				if (!ifindex ||
				    (p->pktinfo.ipi6_ifindex == ifindex))
					ifindex = ifa->ifa_ifindex;
			}
		}
		if (!ifindex) {
			ni_freeifaddrs(ifa0);
			return 1;	/* subject not found */
		}
		if (subj_if)
			*subj_if = ifindex;
	} else {
		ifindex = subj_if ? *subj_if : 0;
		if (ifindex == 0)
			ifindex = p->pktinfo.ipi6_ifindex;
		if (ifindex == 0) {
			ni_freeifaddrs(ifa0);
			return 1;	/* XXX */
		}
	}

	if (reply) {
		struct ni_ifaddrs *ifa;
		unsigned int addrs0 = 0, paddrs0 = 0;
		unsigned int addrs, paddrs = 0, daddrs = 0;

		flags &= ~NI_IPV4ADDR_FLAG_TRUNCATE;

		/* pass 1: count addresses and preferred addresses to be returned */
		for (ifa = ifa0; ifa; ifa = ifa->ifa_next) {
			if (!ifa->ifa_addr)
				continue;
#if 1	/* not used in kernel */
			if (ifa->ifa_flags & (IFA_F_TENTATIVE))
				continue;
#endif
			if (!(flags & NI_NODEADDR_FLAG_ALL) &&
			    ((subj_if && *subj_if) ? (ifa->ifa_ifindex != *subj_if) :
						     (ifa->ifa_ifindex != p->pktinfo.ipi6_ifindex)))
				continue;
			if (filter_ipv4addr((struct in_addr *)ifa->ifa_addr, flags))
				continue;

			if (addrs0 + 1 >= ((MAX_REPLY_SIZE - sizeof(struct icmp6_nodeinfo)) / (sizeof(uint32_t) + sizeof(struct in_addr)))) {
				flags |= NI_IPV4ADDR_FLAG_TRUNCATE;
				break;
			}

			addrs0++;
			if (!(ifa->ifa_flags & IFA_F_DEPRECATED))
				paddrs0++;
		}

		p->reply.ni_type = ICMP6_NI_REPLY;
		p->reply.ni_code = ICMP6_NI_SUCCESS;
		p->reply.ni_cksum = 0;
		p->reply.ni_qtype = htons(NI_QTYPE_IPV4ADDR);
		p->reply.ni_flags = flags & NI_IPV4ADDR_FLAG_ALL;

		/* pass 2: store addresses */
		p->replydatalen = (sizeof(uint32_t)+sizeof(struct in_addr)) * addrs0;
		p->replydata = addrs0 ? ni_malloc(p->replydatalen) : NULL;

		if (p->replydatalen && !p->replydata) {
			p->reply.ni_flags |= NI_NODEADDR_FLAG_TRUNCATE;
			addrs0 = paddrs0 = 0;
		}

		for (ifa = ifa0, addrs = 0; 
		     ifa && addrs < addrs0; 
		     ifa = ifa->ifa_next) {
			char *cp;
			uint32_t ttl;

			if (!ifa->ifa_addr)
				continue;
#if 1	/* not used in kernel */
			if (ifa->ifa_flags & (IFA_F_TENTATIVE))
				continue;
#endif
			if (!(flags & NI_NODEADDR_FLAG_ALL) &&
			    (ifa->ifa_ifindex != ifindex))
				continue;
			if (filter_ipv4addr((struct in_addr *)ifa->ifa_addr, flags))
				continue;	

#if ENABLE_TTL
			if (ifa->ifa_cacheinfo) {
				ttl = ifa->ifa_cacheinfo->ifa_valid > 0x7fffffff ? 
				      htonl(0x7fffffff) : htonl(ifa->ifa_cacheinfo->ifa_valid);
			} else {
				ttl = 0;	/*XXX*/
			}
#else
			ttl = 0;
#endif

			cp = (p->replydata +
			      (sizeof(uint32_t)+sizeof(struct in_addr)) * (ifa->ifa_flags & IFA_F_DEPRECATED ? paddrs0+daddrs : paddrs));
			memcpy(cp, &ttl, sizeof(ttl));
			memcpy(cp + sizeof(ttl), ifa->ifa_addr, sizeof(struct in_addr));

			addrs++;
			if (ifa->ifa_flags & IFA_F_DEPRECATED)
				daddrs++;
			else
				paddrs++;
		}
	}

	ni_freeifaddrs(ifa0);
	return 0;
}

