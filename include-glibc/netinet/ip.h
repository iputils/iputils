#ifndef __NETINET_IP_H
#define __NETINET_IP_H 1

#include <glibc-bugs.h>
#include <netinet/in.h>

#include <linux/ip.h>

#ifdef __USE_BSD
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *
 *	@(#)ip.h	8.1 (Berkeley) 6/10/93
 */

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */

/*
 * Structure of an internet header, naked of options.
 */
struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ip_hl:4;			/* header length */
    u_int8_t ip_v:4;			/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t ip_v:4;			/* version */
    u_int8_t ip_hl:4;			/* header length */
#endif
    u_int8_t ip_tos;			/* type of service */
    u_short ip_len;			/* total length */
    u_short ip_id;			/* identification */
    u_short ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ip_ttl;			/* time to live */
    u_int8_t ip_p;			/* protocol */
    u_short ip_sum;			/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
  };

/*
 * Time stamp option structure.
 */
struct ip_timestamp
  {
    u_int8_t ipt_code;			/* IPOPT_TS */
    u_int8_t ipt_len;			/* size of structure (variable) */
    u_int8_t ipt_ptr;			/* index of current entry */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t ipt_flg:4;			/* flags, see below */
    u_int8_t ipt_oflw:4;		/* overflow counter */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t ipt_oflw:4;		/* overflow counter */
    u_int8_t ipt_flg:4;			/* flags, see below */
#endif
    u_int32_t data[9];
  };
#endif /* __USE_BSD */


#endif /* netinet/ip.h */
