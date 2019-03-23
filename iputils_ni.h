#ifndef IPUTILS_NI_H
#define IPUTILS_NI_H
/*
 * Shared network information definitions.
 */
#include <asm/byteorder.h>

#define IPUTILS_NI_ICMP6_QUERY		139
#define	IPUTILS_NI_ICMP6_REPLY		140

/* NI Codes */
#define IPUTILS_NI_QTYPE_NOOP		0	/* NOOP */
#define IPUTILS_NI_QTYPE_DNSNAME	2	/* DNS Name */
#define IPUTILS_NI_QTYPE_IPV6ADDR	3	/* IPv6 Addresses */
#define IPUTILS_NI_QTYPE_IPV4ADDR	4	/* IPv4 Addresses */

/* ICMP6 codes for NI Query */
#define IPUTILS_NI_ICMP6_SUBJ_IPV6	0	/* Query Subject is an ipv6 address */
#define IPUTILS_NI_ICMP6_SUBJ_FQDN	1	/* Query Subject is a Domain name */
#define IPUTILS_NI_ICMP6_SUBJ_IPV4	2	/* Query Subject is an ipv4 address */

/* ICMP6 codes for NI Reply */
#define IPUTILS_NI_ICMP6_SUCCESS	0	/* NI successful reply */
#define IPUTILS_NI_ICMP6_REFUSED	1	/* NI request is refused */
#define IPUTILS_NI_ICMP6_UNKNOWN	2	/* unknown Qtype */

/* Flags */
#define IPUTILS_NI_IPV6_FLAG_TRUNCATE	__constant_cpu_to_be16(0x0001)
#define IPUTILS_NI_IPV6_FLAG_ALL	__constant_cpu_to_be16(0x0002)
#define IPUTILS_NI_IPV6_FLAG_COMPAT	__constant_cpu_to_be16(0x0004)
#define IPUTILS_NI_IPV6_FLAG_LINKLOCAL	__constant_cpu_to_be16(0x0008)
#define IPUTILS_NI_IPV6_FLAG_SITELOCAL	__constant_cpu_to_be16(0x0010)
#define IPUTILS_NI_IPV6_FLAG_GLOBAL	__constant_cpu_to_be16(0x0020)

#define IPUTILS_NI_FQDN_VALIDTTL	__constant_cpu_to_be16(0x0001)

#define IPUTILS_NI_IPV4_FLAG_TRUNCATE	IPUTILS_NI_IPV6_FLAG_TRUNCATE
#define IPUTILS_NI_IPV4_FLAG_ALL	IPUTILS_NI_IPV6_FLAG_ALL

#endif /* IPUTILS_NI_H */
