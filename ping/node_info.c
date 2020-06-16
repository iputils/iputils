/*
 * Copyright (c) 1989 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stddef.h>

#include "iputils_common.h"
#include "md5.h"
#include "ping.h"

struct niquery_option {
	char *name;
	int namelen;
	int has_arg;
	int data;
	int (*handler)(struct ping_ni *ni, int index, const char *arg);
};

#define NIQUERY_OPTION(_name, _has_arg, _data, _handler)	\
	{							\
		.name = (_name),				\
		.namelen = sizeof(_name) - 1,			\
		.has_arg = (_has_arg),				\
		.data = (_data),				\
		.handler = (_handler)				\
	}

static int niquery_option_name_handler(struct ping_ni *ni, int index __attribute__((__unused__)), const char *arg __attribute__((__unused__)));
static int niquery_option_ipv6_handler(struct ping_ni *ni, int index __attribute__((__unused__)), const char *arg __attribute__((__unused__)));
static int niquery_option_ipv6_flag_handler(struct ping_ni *ni, int index, const char *arg);
static int niquery_option_ipv4_handler(struct ping_ni *ni, int index, const char *arg);
static int niquery_option_ipv4_flag_handler(struct ping_ni *ni, int index, const char *arg);
static int niquery_option_subject_addr_handler(struct ping_ni *ni, int index, const char *arg);
static int niquery_option_subject_name_handler(struct ping_ni *ni, int index, const char *name);
static int niquery_option_help_handler(struct ping_ni *ni, int index, const char *arg);

struct niquery_option niquery_options[] = {
	NIQUERY_OPTION("name",			0,	0,				niquery_option_name_handler),
	NIQUERY_OPTION("fqdn",			0,	0,				niquery_option_name_handler),
	NIQUERY_OPTION("ipv6",			0,	0,				niquery_option_ipv6_handler),
	NIQUERY_OPTION("ipv6-all",		0,	IPUTILS_NI_IPV6_FLAG_ALL,	niquery_option_ipv6_flag_handler),
	NIQUERY_OPTION("ipv6-compatible",	0,	IPUTILS_NI_IPV6_FLAG_COMPAT,	niquery_option_ipv6_flag_handler),
	NIQUERY_OPTION("ipv6-linklocal",	0,	IPUTILS_NI_IPV6_FLAG_LINKLOCAL, niquery_option_ipv6_flag_handler),
	NIQUERY_OPTION("ipv6-sitelocal",	0,	IPUTILS_NI_IPV6_FLAG_SITELOCAL, niquery_option_ipv6_flag_handler),
	NIQUERY_OPTION("ipv6-global",		0,	IPUTILS_NI_IPV6_FLAG_GLOBAL,	niquery_option_ipv6_flag_handler),
	NIQUERY_OPTION("ipv4",			0,	0,				niquery_option_ipv4_handler),
	NIQUERY_OPTION("ipv4-all",		0,	IPUTILS_NI_IPV4_FLAG_ALL,	niquery_option_ipv4_flag_handler),
	NIQUERY_OPTION("subject-ipv6",		1,	IPUTILS_NI_ICMP6_SUBJ_IPV6,	niquery_option_subject_addr_handler),
	NIQUERY_OPTION("subject-ipv4",		1,	IPUTILS_NI_ICMP6_SUBJ_IPV4,	niquery_option_subject_addr_handler),
	NIQUERY_OPTION("subject-name",		1,	0,				niquery_option_subject_name_handler),
	NIQUERY_OPTION("subject-fqdn",		1,	-1,				niquery_option_subject_name_handler),
	NIQUERY_OPTION("help",			0,	0,				niquery_option_help_handler),
	{NULL, 0, 0, 0, NULL}
};

int niquery_is_enabled(struct ping_ni *ni)
{
	return ni->query >= 0;
}

void niquery_init_nonce(struct ping_ni *ni)
{
#if PING6_NONCE_MEMORY
	ni->nonce_ptr = calloc(NI_NONCE_SIZE, MAX_DUP_CHK);
	if (!ni->nonce_ptr)
		error(2, errno, "calloc");

	ni->nonce_ptr[0] = ~0;
#else
	gettimeofday(&ni->nonce_secret.tv, NULL);
	ni->nonce_secret.pid = getpid();
#endif
}

#if !PING6_NONCE_MEMORY
static int niquery_nonce(struct ping_ni *ni, uint8_t *nonce, int fill)
{
	static uint8_t digest[IPUTILS_MD5LENGTH];
	static int seq = -1;

	if (fill || seq != *(uint16_t *)nonce || seq == -1) {
		IPUTILS_MD5_CTX ctxt;

		iputils_MD5Init(&ctxt);
		iputils_MD5Update(&ctxt, (const char *)&ni->nonce_secret,
				  sizeof(ni->nonce_secret));
		iputils_MD5Update(&ctxt, (const char *)nonce, sizeof(uint16_t));
		iputils_MD5Final(digest, &ctxt);

		seq = *(uint16_t *)nonce;
	}

	if (fill) {
		memcpy(nonce + sizeof(uint16_t), digest, NI_NONCE_SIZE - sizeof(uint16_t));
		return 0;
	}

	if (memcmp(nonce + sizeof(uint16_t), digest, NI_NONCE_SIZE - sizeof(uint16_t)))
		return -1;

	return ntohsp((uint16_t *)nonce);
}
#endif

void niquery_fill_nonce(struct ping_ni *ni, uint16_t seq, uint8_t *nonce)
{
	uint16_t v = htons(seq);
#if PING6_NONCE_MEMORY
	int i;

	memcpy(&ni->nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK)], &v, sizeof(v));

	for (i = sizeof(v); i < NI_NONCE_SIZE; i++)
		ni->nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK) + i] = 0x100 * (rand() / (RAND_MAX + 1.0));

	memcpy(nonce, &ni->nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK)], NI_NONCE_SIZE);
#else
	memcpy(nonce, &v, sizeof(v));
	niquery_nonce(ni, nonce, 1);
#endif
}

int niquery_check_nonce(struct ping_ni *ni, uint8_t *nonce)
{
#if PING6_NONCE_MEMORY
	uint16_t seq = ntohsp((uint16_t *)nonce);
	if (memcmp(nonce, &ni->nonce_ptr[NI_NONCE_SIZE * (seq % MAX_DUP_CHK)], NI_NONCE_SIZE))
		return -1;
	return seq;
#else
	return niquery_nonce(ni, nonce, 0);
#endif
}

static int niquery_set_qtype(struct ping_ni *ni, int type)
{
	if (niquery_is_enabled(ni) && ni->query != type) {
		printf(_("Qtype conflict\n"));
		return -1;
	}
	ni->query = type;
	return 0;
}

static int niquery_option_name_handler(struct ping_ni *ni, int index __attribute__((__unused__)), const char *arg __attribute__((__unused__)))
{
	if (niquery_set_qtype(ni, IPUTILS_NI_QTYPE_DNSNAME) < 0)
		return -1;
	return 0;
}

static int niquery_option_ipv6_handler(struct ping_ni *ni, int index __attribute__((__unused__)), const char *arg __attribute__((__unused__)))
{
	if (niquery_set_qtype(ni, IPUTILS_NI_QTYPE_IPV6ADDR) < 0)
		return -1;
	return 0;
}

static int niquery_option_ipv6_flag_handler(struct ping_ni *ni, int index, const char *arg __attribute__((__unused__)))
{
	if (niquery_set_qtype(ni, IPUTILS_NI_QTYPE_IPV6ADDR) < 0)
		return -1;
	ni->flag |= niquery_options[index].data;
	return 0;
}

static int niquery_option_ipv4_handler(struct ping_ni *ni, int index __attribute__((__unused__)), const char *arg __attribute__((__unused__)))
{
	if (niquery_set_qtype(ni, IPUTILS_NI_QTYPE_IPV4ADDR) < 0)
		return -1;
	return 0;
}

static int niquery_option_ipv4_flag_handler(struct ping_ni *ni, int index, const char *arg __attribute__((__unused__)))
{
	if (niquery_set_qtype(ni, IPUTILS_NI_QTYPE_IPV4ADDR) < 0)
		return -1;
	ni->flag |= niquery_options[index].data;
	return 0;
}

int niquery_is_subject_valid(struct ping_ni *ni)
{
	return ni->subject_type >= 0 && ni->subject;
}

static int niquery_set_subject_type(struct ping_ni *ni, int type)
{
	if (niquery_is_subject_valid(ni) && ni->subject_type != type) {
		printf(_("Subject type conflict\n"));
		return -1;
	}
	ni->subject_type = type;
	return 0;
}

static int niquery_option_subject_addr_handler(struct ping_ni *ni, int index, const char *arg)
{
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = getaddrinfo_flags
	};
	struct addrinfo *result, *ai;
	int ret_val;
	int offset;

	if (niquery_set_subject_type(ni, niquery_options[index].data) < 0)
		return -1;

	ni->subject_type = niquery_options[index].data;

	switch (niquery_options[index].data) {
	case IPUTILS_NI_ICMP6_SUBJ_IPV6:
		ni->subject_len = sizeof(struct in6_addr);
		offset = offsetof(struct sockaddr_in6, sin6_addr);
		hints.ai_family = AF_INET6;
		break;
	case IPUTILS_NI_ICMP6_SUBJ_IPV4:
		ni->subject_len = sizeof(struct in_addr);
		offset = offsetof(struct sockaddr_in, sin_addr);
		hints.ai_family = AF_INET;
		break;
	default:
		/* should not happen. */
		offset = -1;
	}

	ret_val = getaddrinfo(arg, 0, &hints, &result);
	if (ret_val) {
		error(0, 0, "%s: %s", arg, gai_strerror(ret_val));
		return -1;
	}

	for (ai = result; ai; ai = ai->ai_next) {
		void *p = malloc(ni->subject_len);
		if (!p)
			continue;
		memcpy(p, (uint8_t *)ai->ai_addr + offset, ni->subject_len);
		free(ni->subject);
		ni->subject = p;
		break;
	}
	freeaddrinfo(result);

	return 0;
}

#ifdef USE_IDN
# if IDN2_VERSION_NUMBER >= 0x02000000
#  define IDN2_FLAGS IDN2_NONTRANSITIONAL
# else
#  define IDN2_FLAGS 0
# endif
#endif

static int niquery_option_subject_name_handler(struct ping_ni *ni, int index, const char *name)
{
	static char nigroup_buf[INET6_ADDRSTRLEN + 1 + IFNAMSIZ];
	unsigned char *dnptrs[2], **dpp, **lastdnptr;
	int n;
	size_t i;
	char *p;
	char *canonname = NULL, *idn = NULL;
	char *buf = NULL;
	size_t namelen;
	size_t buflen;
	int dots, fqdn = niquery_options[index].data;
	IPUTILS_MD5_CTX ctxt;
	uint8_t digest[IPUTILS_MD5LENGTH];
#ifdef USE_IDN
	int rc;
#endif

	if (niquery_set_subject_type(ni, IPUTILS_NI_ICMP6_SUBJ_FQDN) < 0)
		return -1;

#ifdef USE_IDN
	rc = idn2_lookup_ul(name, &idn, IDN2_FLAGS);
	if (rc)
		error(2, 0, _("IDN encoding error: %s"), idn2_strerror(rc));
#else
	idn = strdup(name);
	if (!idn)
		goto oomexit;
#endif

	p = strchr(idn, SCOPE_DELIMITER);
	if (p) {
		*p = '\0';
		if (strlen(p + 1) >= IFNAMSIZ)
			error(1, 0, _("too long scope name"));
	}

	namelen = strlen(idn);
	canonname = malloc(namelen + 1);
	if (!canonname)
		goto oomexit;

	dots = 0;
	for (i = 0; i < namelen + 1; i++) {
		canonname[i] = isupper(idn[i]) ? tolower(idn[i]) : idn[i];
		if (idn[i] == '.')
			dots++;
	}

	if (fqdn == 0) {
		/* guess if hostname is FQDN */
		fqdn = dots ? 1 : -1;
	}

	buflen = namelen + 3 + 1;	/* dn_comp() requires strlen() + 3,
					   plus non-fqdn indicator. */
	buf = malloc(buflen);
	if (!buf) {
		error(0, errno, _("memory allocation failed"));
		goto errexit;
	}

	dpp = dnptrs;
	lastdnptr = &dnptrs[ARRAY_SIZE(dnptrs)];

	*dpp++ = (unsigned char *)buf;
	*dpp++ = NULL;

	n = dn_comp(canonname, (unsigned char *)buf, buflen, dnptrs, lastdnptr);
	if (n < 0) {
		error(0, 0, _("inappropriate subject name: %s"), canonname);
		goto errexit;
	} else if ((size_t)n >= buflen) {
		error(0, 0, _("dn_comp() returned too long result"));
		goto errexit;
	}

	iputils_MD5Init(&ctxt);
	iputils_MD5Update(&ctxt, buf, buf[0]);
	iputils_MD5Final(digest, &ctxt);

	sprintf(nigroup_buf, "ff02::2:%02x%02x:%02x%02x%s%s",
		digest[0], digest[1], digest[2], digest[3],
		p ? "%" : "",
		p ? p + 1 : "");

	if (fqdn < 0)
		buf[n] = 0;

	free(ni->subject);

	ni->group = nigroup_buf;
	ni->subject = buf;
	ni->subject_len = n + (fqdn < 0);

	free(canonname);
	free(idn);

	return 0;
oomexit:
	error(0, errno, _("memory allocation failed"));
errexit:
	free(buf);
	free(canonname);
	free(idn);
	exit(1);
}

int niquery_option_help_handler(struct ping_ni *ni __attribute__((__unused__)),
				int index,
				const char *arg __attribute__((__unused__)))
{
	fprintf(index ? stdout : stderr,
		      _("ping -6 -N <nodeinfo opt>\n"
			"Help:\n"
			"  help\n"
			"Query:\n"
			"  name\n"
			"  ipv6\n"
			"  ipv6-all\n"
			"  ipv6-compatible\n"
			"  ipv6-global\n"
			"  ipv6-linklocal\n"
			"  ipv6-sitelocal\n"
			"  ipv4\n"
			"  ipv4-all\n"
			"Subject:\n"
			"  subject-ipv6=addr\n"
			"  subject-ipv4=addr\n"
			"  subject-name=name\n"
			"  subject-fqdn=name\n"
		));
	index ? exit(0) : exit(2);
}

int niquery_option_handler(struct ping_ni *ni, const char *opt_arg)
{
	struct niquery_option *p;
	int i;
	int ret = -1;
	for (i = 0, p = niquery_options; p->name; i++, p++) {
		if (strncmp(p->name, opt_arg, p->namelen))
			continue;
		if (!p->has_arg) {
			if (opt_arg[p->namelen] == '\0') {
				ret = p->handler(ni, i, NULL);
				if (ret >= 0)
					break;
			}
		} else {
			if (opt_arg[p->namelen] == '=') {
				ret = p->handler(ni, i, &opt_arg[p->namelen] + 1);
				if (ret >= 0)
					break;
			}
		}
	}
	if (!p->name)
		ret = niquery_option_help_handler(ni, 0, NULL);
	return ret;
}
