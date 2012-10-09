/*
 * Copyright (C) 2002 USAGI/WIDE Project.
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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

#ifndef ICMP6_NODEINFO_H
#define ICMP6_NODEINFO_H

struct icmp6_nodeinfo {
	struct icmp6_hdr	icmp6_ni_hdr;
	uint8_t			icmp6_ni_nonce[8];
	/* could be followed by reply data */
};

#define ni_type		icmp6_ni_hdr.icmp6_type
#define ni_code		icmp6_ni_hdr.icmp6_code
#define ni_cksum	icmp6_ni_hdr.icmp6_cksum
#define ni_qtype	icmp6_ni_hdr.icmp6_data16[0]
#define ni_flags	icmp6_ni_hdr.icmp6_data16[1]
#define ni_nonce	icmp6_ni_nonce

/* ICMP6 types */
#define ICMP6_NI_QUERY			139
#define ICMP6_NI_REPLY			140

/* ICMP6 codes for NI Query */
#define ICMP6_NI_SUBJ_IPV6		0	/* Query Subject is an ipv6 address */
#define ICMP6_NI_SUBJ_FQDN		1	/* Query Subject is a Domain name */
#define ICMP6_NI_SUBJ_IPV4		2	/* Query Subject is an ipv4 address */

/* ICMP6 codes for NI Reply */
#define ICMP6_NI_SUCCESS		0	/* NI successful reply */
#define ICMP6_NI_REFUSED		1	/* NI request is refused */
#define ICMP6_NI_UNKNOWN		2	/* unknown Qtype */

/* NI Codes */
#define NI_QTYPE_NOOP			0	/* NOOP  */
#define NI_QTYPE_SUPTYPES		1	/* Supported Qtypes */
#define NI_QTYPE_DNSNAME		2	/* DNS Name */
#define NI_QTYPE_NODEADDR		3	/* Node Addresses */
#define NI_QTYPE_IPV4ADDR		4	/* IPv4 Addresses */

/* NI Flags */
#if WORDS_BIGENDIAN
#define NI_SUPTYPE_FLAG_COMPRESS	0x1
#define NI_FQDN_FLAG_VALIDTTL		0x1
#else
#define NI_SUPTYPE_FLAG_COMPRESS	0x0100
#define NI_FQDN_FLAG_VALIDTTL		0x0100
#endif

#if WORDS_BIGENDIAN
#define NI_NODEADDR_FLAG_TRUNCATE	0x1
#define NI_NODEADDR_FLAG_ALL		0x2
#define NI_NODEADDR_FLAG_COMPAT		0x4
#define NI_NODEADDR_FLAG_LINKLOCAL	0x8
#define NI_NODEADDR_FLAG_SITELOCAL	0x10
#define NI_NODEADDR_FLAG_GLOBAL		0x20
#else
#define NI_NODEADDR_FLAG_TRUNCATE	0x0100
#define NI_NODEADDR_FLAG_ALL		0x0200
#define NI_NODEADDR_FLAG_COMPAT		0x0400
#define NI_NODEADDR_FLAG_LINKLOCAL	0x0800
#define NI_NODEADDR_FLAG_SITELOCAL	0x1000
#define NI_NODEADDR_FLAG_GLOBAL		0x2000
#endif

#define NI_IPV4ADDR_FLAG_TRUNCATE	NI_NODEADDR_FLAG_TRUNCATE
#define NI_IPV4ADDR_FLAG_ALL		NI_NODEADDR_FLAG_ALL

#endif

