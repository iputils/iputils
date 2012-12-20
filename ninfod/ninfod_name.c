/* $USAGI: ninfod_name.c,v 1.15 2003-01-11 14:33:28 yoshfuji Exp $ */
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
# include <ctype.h>
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

#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#if HAVE_NETINET_ICMP6_H
# include <netinet/icmp6.h>
#endif
#ifndef HAVE_STRUCT_ICMP6_NODEINFO
# include "icmp6_nodeinfo.h"
#endif

#include <arpa/inet.h>

#if defined(HAVE_GNUTLS_OPENSSL_H)
# include <gnutls/openssl.h>
#elif defined(HAVE_OPENSSL_MD5_H)
# include <openssl/md5.h>
#endif

#if HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
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

/* Hmm,,, */
#ifndef IPV6_JOIN_GROUP
# define IPV6_JOIN_GROUP	IPV6_ADD_MEMBERSHIP
# define IPV6_LEAVE_GROUP	IPV6_DROP_MEMBERSHIP
#endif

/* ---------- */
/* ID */
static char *RCSID __attribute__ ((unused)) = "$USAGI: ninfod_name.c,v 1.15 2003-01-11 14:33:28 yoshfuji Exp $";

/* Variables */
static struct utsname utsname;
static char *uts_nodename = utsname.nodename;

char nodename[MAX_DNSNAME_SIZE];
static size_t nodenamelen;

static struct ipv6_mreq nigroup;

/* ---------- */
/* Functions */
int check_nigroup(const struct in6_addr *addr)
{
	return IN6_IS_ADDR_MULTICAST(&nigroup.ipv6mr_multiaddr) &&
	       IN6_ARE_ADDR_EQUAL(&nigroup.ipv6mr_multiaddr, addr);
}

static int encode_dnsname(const char *name, 
			  char *buf, size_t buflen, 
			  int fqdn)
{
	size_t namelen;
	int i;

	if (buflen < 0)
		return -1;

	namelen = strlen(name);
	if (namelen == 0)
		return 0;
	if (namelen > 255 || buflen < namelen+1)
		return -1;

	i = 0;
	while(i <= namelen) {
		const char *e;
		int llen, ii;

		e = strchr(&name[i], '.');
		if (e == NULL)
			e = name + namelen;
		llen = e - &name[i];
		if (llen == 0) {
			if (*e)
				return -1;
			if (fqdn < 0)
				return -1;
			fqdn = 1;
			break;
		}
		if (llen >= 0x40)
			return -1;
		buf[i] = llen;
		for (ii = 0; ii < llen; ii++) {
			if (!isascii(name[i+ii]))
				return -1;
			if (ii == 0 || ii == llen-1) {
				if (!isalpha(name[i+ii]) && !isdigit(name[i+ii]))
					return -1;
			} else if (!isalnum(name[i+ii]) && name[i+ii] != '-')
				return -1;
			buf[i+ii+1] = isupper(name[i+ii]) ? tolower(name[i+ii]) : name[i+ii];
		}
		i += llen + 1;
	}
	if (buflen < i + 1 + !(fqdn > 0))
		return -1;
	buf[i++] = 0;
	if (!(fqdn > 0))
		buf[i++] = 0;
	return i;
}

static int compare_dnsname(const char *s, size_t slen,
			   const char *n, size_t nlen)
{
	const char *s0 = s, *n0 = n;
	int done = 0, retcode = 0;
	if (slen < 1 || nlen < 1)
		return -1;	/* invalid length */
	/* simple case */
	if (slen == nlen && memcmp(s, n, slen) == 0)
		return 0;
	if (*(s0 + slen - 1) || *(n0 + nlen - 1))
		return -1;	/* invalid termination */
	while (s < s0 + slen && n < n0 + nlen) {
		if (*s >= 0x40 || *n >= 0x40)
			return -1;	/* DNS compression is not allowed here */
		if (s + *s + 1 > s0 + slen || n + *n + 1 > n0 + nlen)
			return -1;	/* overrun */
		if (*s == '\0') {
			if (s == s0 + slen - 1)
				break;	/* FQDN */
			else if (s + 1 == s0 + slen - 1)
				return retcode;	/* truncated */
			else
				return -1;	/* more than one subject */
		}
		if (!done) {
			if (*n == '\0') {
				if (n == n0 + nlen - 1) {
					done = 1;	/* FQDN */
				} else if (n + 1 == n0 + nlen - 1) {
					retcode = 1;	// trunc
					done = 1;
				} else
					return -1;
			} else {
				if (*s != *n) {
					done = 1;
					retcode = 1;
				} else {
					if (memcmp(s+1, n+1, *s)) {
						done = 1;
						retcode = 1;
					}
				}
			}
		}
		s += *s + 1;
		n += done ? 0 : (*n + 1);
	}
	return retcode;
}

static int nodeinfo_group(const char *dnsname, int namelen, 
			  struct in6_addr *nigroup)
{
	MD5_CTX ctxt;
	unsigned char digest[16];

	if (!dnsname || !nigroup)
		return -1;

	MD5_Init(&ctxt);
	MD5_Update(&ctxt, dnsname, *dnsname);
	MD5_Final(digest, &ctxt);

#ifdef s6_addr32
	nigroup->s6_addr32[0] = htonl(0xff020000);
	nigroup->s6_addr32[1] = 0;
	nigroup->s6_addr32[2] = htonl(0x00000002);
#else
	memset(nigroup, 0, sizeof(*nigroup));
	nigroup->s6_addr[ 0] = 0xff;
	nigroup->s6_addr[ 1] = 0x02;
	nigroup->s6_addr[11] = 0x02;
#endif
	memcpy(&nigroup->s6_addr[12], digest, 4);

	return 0;
}

/* ---------- */
void init_nodeinfo_nodename(int forced)
{
	struct utsname newname;
	int len;
	int changed = 0;

	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	uname(&newname);
	changed = strcmp(newname.nodename, utsname.nodename);

	if (!changed && !forced)
		return;

	memcpy(&utsname, &newname, sizeof(newname));

	/* leave old group */
	if ((changed || forced) && !IN6_IS_ADDR_UNSPECIFIED(&nigroup.ipv6mr_multiaddr)) {
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &nigroup, sizeof(nigroup)) < 0) {
#if ENABLE_DEBUG
			char niaddrbuf[INET6_ADDRSTRLEN];
			if (inet_ntop(AF_INET6, &nigroup, niaddrbuf, sizeof(niaddrbuf)) == NULL)
				strcpy(niaddrbuf, "???");
#endif
			DEBUG(LOG_WARNING,
			      "%s(): failed to leave group %s.\n",
			      __func__, niaddrbuf);
			memset(&nigroup, 0, sizeof(nigroup));
		}
	}

	len = encode_dnsname(uts_nodename,
			     nodename, 
			     sizeof(nodename),
			     0);

	/* setup ni reply */
	nodenamelen = len > 0 ? len : 0;

	/* setup ni group */
	if (changed || forced) {
		if (nodenamelen) {
			memset(&nigroup, 0, sizeof(nigroup));
			nodeinfo_group(nodename, len, &nigroup.ipv6mr_multiaddr);
			nigroup.ipv6mr_interface = 0;
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &nigroup, sizeof(nigroup)) < 0) {
#if ENABLE_DEBUG
				char niaddrbuf[INET6_ADDRSTRLEN];
				if (inet_ntop(AF_INET6, &nigroup, niaddrbuf, sizeof(niaddrbuf)) == NULL)
					strcpy(niaddrbuf, "???");
#endif
				DEBUG(LOG_WARNING,
				      "%s(): failed to join group %s.\n",
				      __func__, niaddrbuf);
				memset(&nigroup, 0, sizeof(nigroup));
			}
		} else {
			memset(&nigroup, 0, sizeof(nigroup));
		}
	}

	return;
}

/* ---------- */
/* nodename */
int pr_nodeinfo_nodename(CHECKANDFILL_ARGS)
{
	DEBUG(LOG_DEBUG, "%s()\n", __func__);

	if (subject) {
		if (!nodenamelen ||
		    compare_dnsname(subject, subjlen, 
				    nodename, 
				    nodenamelen))
			return 1;
		if (subj_if)
			*subj_if = p->pktinfo.ipi6_ifindex;
	}

	if (reply) {
		uint32_t ttl = 0;

		p->reply.ni_type = ICMP6_NI_REPLY;
		p->reply.ni_code = ICMP6_NI_SUCCESS;
		p->reply.ni_cksum = 0;
		p->reply.ni_qtype = htons(NI_QTYPE_DNSNAME);
		p->reply.ni_flags = 0;

		p->replydatalen = nodenamelen ? sizeof(ttl)+nodenamelen : 0;
		p->replydata = nodenamelen ? ni_malloc(p->replydatalen) : NULL;
		if (p->replydata) {
			memcpy(p->replydata, &ttl, sizeof(ttl));
			memcpy(p->replydata + sizeof(ttl), &nodename, nodenamelen);
		}
	}

	return 0;
}

