/* $USAGI: ni_ifaddrs.c,v 1.8 2007-10-11 06:25:21 yoshfuji Exp $ */
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

/* reformatted by indent -kr -i8 -l 1000 */
/* USAGI: ifaddrs.c,v 1.18 2002/03/06 01:50:46 yoshfuji Exp */

/**************************************************************************
 * ifaddrs.c
 * Copyright (C)2000 Hideaki YOSHIFUJI, All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <string.h>
#include <time.h>
#include <malloc.h>
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>	/* the L2 protocols */
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_arp.h>
#include "ni_ifaddrs.h"
#include <netinet/in.h>

#ifdef _USAGI_LIBINET6
#include "libc-compat.h"
#endif

//#define IFA_LOCAL	IFA_LOCAL

static const char *RCSID __attribute__ ((unused)) = "$USAGI: ni_ifaddrs.c,v 1.8 2007-10-11 06:25:21 yoshfuji Exp $ based on USAGI: ifaddrs.c,v 1.18 2002/03/06 01:50:46 yoshfuji Exp";

/* ====================================================================== */
struct nlmsg_list {
	struct nlmsg_list *nlm_next;
	struct nlmsghdr *nlh;
	int size;
	time_t seq;
};

#ifndef IFA_LOCAL
struct rtmaddr_ifamap {
	void *address;
	void *local;
	void *broadcast;
	int address_len;
	int local_len;
	int broadcast_len;
};
#endif

/* ====================================================================== */
static int nl_sendreq(int sd, int request, int flags, int *seq)
{
	char reqbuf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) + NLMSG_ALIGN(sizeof(struct rtgenmsg))];
	struct sockaddr_nl nladdr;
	struct nlmsghdr *req_hdr;
	struct rtgenmsg *req_msg;
	time_t t = time(NULL);

	if (seq)
		*seq = t;
	memset(&reqbuf, 0, sizeof(reqbuf));
	req_hdr = (struct nlmsghdr *) reqbuf;
	req_msg = (struct rtgenmsg *) NLMSG_DATA(req_hdr);
	req_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*req_msg));
	req_hdr->nlmsg_type = request;
	req_hdr->nlmsg_flags = flags | NLM_F_REQUEST;
	req_hdr->nlmsg_pid = 0;
	req_hdr->nlmsg_seq = t;
	req_msg->rtgen_family = AF_UNSPEC;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	return (sendto(sd, (void *) req_hdr, req_hdr->nlmsg_len, 0, (struct sockaddr *) &nladdr, sizeof(nladdr)));
}

static int nl_recvmsg(int sd, int request, int seq, void *buf, size_t buflen, int *flags)
{
	struct msghdr msg;
	struct iovec iov = { buf, buflen };
	struct sockaddr_nl nladdr;
	int read_len;

	for (;;) {
		msg.msg_name = (void *) &nladdr;
		msg.msg_namelen = sizeof(nladdr);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
		msg.msg_flags = 0;
		read_len = recvmsg(sd, &msg, 0);
		if ((read_len < 0 && errno == EINTR)
		    || (msg.msg_flags & MSG_TRUNC))
			continue;
		if (flags)
			*flags = msg.msg_flags;
		break;
	}
	return read_len;
}

static int nl_getmsg(int sd, int request, int seq, struct nlmsghdr **nlhp, int *done)
{
	struct nlmsghdr *nh;
	size_t bufsize = 65536, lastbufsize = 0;
	void *buff = NULL;
	int result = 0, read_size;
	int msg_flags;
	pid_t pid = getpid();
	for (;;) {
		void *newbuff = realloc(buff, bufsize);
		if (newbuff == NULL || bufsize < lastbufsize) {
			free(newbuff);
			result = -1;
			break;
		}
		buff = newbuff;
		result = read_size = nl_recvmsg(sd, request, seq, buff, bufsize, &msg_flags);
		if (read_size < 0 || (msg_flags & MSG_TRUNC)) {
			lastbufsize = bufsize;
			bufsize *= 2;
			continue;
		}
		if (read_size == 0)
			break;
		nh = (struct nlmsghdr *) buff;
		for (nh = (struct nlmsghdr *) buff; NLMSG_OK(nh, read_size); nh = (struct nlmsghdr *) NLMSG_NEXT(nh, read_size)) {
			if (nh->nlmsg_pid != pid || nh->nlmsg_seq != seq)
				continue;
			if (nh->nlmsg_type == NLMSG_DONE) {
				(*done)++;
				break;	/* ok */
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(nh);
				result = -1;
				if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
					errno = EIO;
				else
					errno = -nlerr->error;
				break;
			}
		}
		break;
	}
	if (result < 0)
		if (buff) {
			int saved_errno = errno;
			free(buff);
			buff = NULL;
			errno = saved_errno;
		}
	*nlhp = (struct nlmsghdr *) buff;
	return result;
}

static int nl_getlist(int sd, int seq, int request, struct nlmsg_list **nlm_list, struct nlmsg_list **nlm_end)
{
	struct nlmsghdr *nlh = NULL;
	int status;
	int done = 0;

	status = nl_sendreq(sd, request, NLM_F_ROOT | NLM_F_MATCH, &seq);
	if (status < 0)
		return status;
	if (seq == 0)
		seq = (int) time(NULL);
	while (!done) {
		status = nl_getmsg(sd, request, seq, &nlh, &done);
		if (status < 0)
			return status;
		if (nlh) {
			struct nlmsg_list *nlm_next = (struct nlmsg_list *) malloc(sizeof(struct nlmsg_list));
			if (nlm_next == NULL) {
				int saved_errno = errno;
				free(nlh);
				errno = saved_errno;
				status = -1;
			} else {
				nlm_next->nlm_next = NULL;
				nlm_next->nlh = (struct nlmsghdr *) nlh;
				nlm_next->size = status;
				nlm_next->seq = seq;
				if (*nlm_list == NULL) {
					*nlm_list = nlm_next;
					*nlm_end = nlm_next;
				} else {
					(*nlm_end)->nlm_next = nlm_next;
					*nlm_end = nlm_next;
				}
			}
		}
	}
	return status >= 0 ? seq : status;
}

/* ---------------------------------------------------------------------- */
static void free_nlmsglist(struct nlmsg_list *nlm0)
{
	struct nlmsg_list *nlm, *nlm_next;
	int saved_errno;
	if (!nlm0)
		return;
	saved_errno = errno;
	nlm = nlm0;
	while(nlm) {
		if(nlm->nlh)
			free(nlm->nlh);
		nlm_next = nlm->nlm_next;
		free(nlm);
		nlm = nlm_next;
	}
	errno = saved_errno;
}

static void free_data(void *data)
{
	int saved_errno = errno;
	if (data != NULL)
		free(data);
	errno = saved_errno;
}

/* ---------------------------------------------------------------------- */
static void nl_close(int sd)
{
	int saved_errno = errno;
	if (sd >= 0)
		close(sd);
	errno = saved_errno;
}

/* ---------------------------------------------------------------------- */
static int nl_open(void)
{
	struct sockaddr_nl nladdr;
	int sd;

	sd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sd < 0)
		return -1;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	if (bind(sd, (struct sockaddr *) &nladdr, sizeof(nladdr)) < 0) {
		nl_close(sd);
		return -1;
	}
	return sd;
}

/* ====================================================================== */
int ni_ifaddrs(struct ni_ifaddrs **ifap, sa_family_t family)
{
	int sd;
	struct nlmsg_list *nlmsg_list, *nlmsg_end, *nlm;
	/* - - - - - - - - - - - - - - - */
	int icnt;
	size_t dlen, xlen;
	uint32_t max_ifindex = 0;

	pid_t pid = getpid();
	int seq = 0;
	int result;
	int build;		/* 0 or 1 */

/* ---------------------------------- */
	/* initialize */
	icnt = dlen = xlen = 0;
	nlmsg_list = nlmsg_end = NULL;

	if (ifap)
		*ifap = NULL;

/* ---------------------------------- */
	/* open socket and bind */
	sd = nl_open();
	if (sd < 0)
		return -1;

/* ---------------------------------- */
	/* gather info */
	if ((seq = nl_getlist(sd, seq + 1, RTM_GETADDR, &nlmsg_list, &nlmsg_end)) < 0) {
		free_nlmsglist(nlmsg_list);
		nl_close(sd);
		return -1;
	}

/* ---------------------------------- */
	/* Estimate size of result buffer and fill it */
	for (build = 0; build <= 1; build++) {
		struct ni_ifaddrs *ifl = NULL, *ifa = NULL;
		struct nlmsghdr *nlh, *nlh0;
		void *data = NULL, *xdata = NULL;
		uint16_t *ifflist = NULL;
#ifndef IFA_LOCAL
		struct rtmaddr_ifamap ifamap;
#endif

		if (build) {
			ifa = data = calloc(1, NLMSG_ALIGN(sizeof(struct ni_ifaddrs[icnt]))
					    + dlen + xlen);
			if (ifap != NULL)
				*ifap = ifa;
			else {
				free_data(data);
				result = 0;
				break;
			}
			if (data == NULL) {
				free_data(data);
				result = -1;
				break;
			}
			ifl = NULL;
			data += NLMSG_ALIGN(sizeof(struct ni_ifaddrs)) * icnt;
			xdata = data + dlen;
			ifflist = xdata + xlen;
		}

		for (nlm = nlmsg_list; nlm; nlm = nlm->nlm_next) {
			int nlmlen = nlm->size;
			if (!(nlh0 = nlm->nlh))
				continue;
			for (nlh = nlh0; NLMSG_OK(nlh, nlmlen); nlh = NLMSG_NEXT(nlh, nlmlen)) {
				struct ifaddrmsg *ifam = NULL;
				struct rtattr *rta;

				size_t nlm_struct_size = 0;
				sa_family_t nlm_family = 0;
				uint32_t nlm_scope = 0, nlm_index = 0;
				unsigned int nlm_flags;
				size_t rtasize;

#ifndef IFA_LOCAL
				memset(&ifamap, 0, sizeof(ifamap));
#endif

				/* check if the message is what we want */
				if (nlh->nlmsg_pid != pid || nlh->nlmsg_seq != nlm->seq)
					continue;
				if (nlh->nlmsg_type == NLMSG_DONE) {
					break;	/* ok */
				}
				switch (nlh->nlmsg_type) {
				case RTM_NEWADDR:
					ifam = (struct ifaddrmsg *) NLMSG_DATA(nlh);
					nlm_struct_size = sizeof(*ifam);
					nlm_family = ifam->ifa_family;
					nlm_scope = ifam->ifa_scope;
					nlm_index = ifam->ifa_index;
					nlm_flags = ifam->ifa_flags;
					if (family && nlm_family != family)
						continue;
					if (build) {
						ifa->ifa_ifindex = nlm_index;
						ifa->ifa_flags = nlm_flags;
					}
					break;
				default:
					continue;
				}

				if (!build) {
					if (max_ifindex < nlm_index)
						max_ifindex = nlm_index;
				} else {
					if (ifl != NULL)
						ifl->ifa_next = ifa;
				}

				rtasize = NLMSG_PAYLOAD(nlh, nlmlen) - NLMSG_ALIGN(nlm_struct_size);
				for (rta = (struct rtattr *) (((char *) NLMSG_DATA(nlh)) + 
									NLMSG_ALIGN(nlm_struct_size)); 
				     RTA_OK(rta, rtasize); 
				     rta = RTA_NEXT(rta, rtasize)) {
					void *rtadata = RTA_DATA(rta);
					size_t rtapayload = RTA_PAYLOAD(rta);

					switch (nlh->nlmsg_type) {
					case RTM_NEWADDR:
						if (nlm_family == AF_PACKET)
							break;
						switch (rta->rta_type) {
#ifndef IFA_LOCAL
						case IFA_ADDRESS:
							ifamap.address = rtadata;
							ifamap.address_len = rtapayload;
							break;
						case IFA_LOCAL:
							ifamap.local = rtadata;
							ifamap.local_len = rtapayload;
							break;
						case IFA_BROADCAST:
							ifamap.broadcast = rtadata;
							ifamap.broadcast_len = rtapayload;
							break;
						case IFA_LABEL:
							break;
						case IFA_UNSPEC:
							break;
#else
						case IFA_LOCAL:
							if (!build)
								dlen += NLMSG_ALIGN(rtapayload);
							else {
								memcpy(data, rtadata, rtapayload);
								ifa->ifa_addr = data;
								data += NLMSG_ALIGN(rtapayload);
							}
							break;
#endif
						case IFA_CACHEINFO:
							if (!build)
								xlen += NLMSG_ALIGN(rtapayload);
							else {
								memcpy(xdata, rtadata, rtapayload);
								ifa->ifa_cacheinfo = xdata;
								xdata += NLMSG_ALIGN(rtapayload);
							}
							break;
						}
					}
				}
#ifndef IFA_LOCAL
				if (nlh->nlmsg_type == RTM_NEWADDR && nlm_family != AF_PACKET) {
					if (!ifamap.local) {
						ifamap.local = ifamap.address;
						ifamap.local_len = ifamap.address_len;
					}
					if (!ifamap.address) {
						ifamap.address = ifamap.local;
						ifamap.address_len = ifamap.local_len;
					}
					if (ifamap.address_len != ifamap.local_len || 
					    (ifamap.address != NULL && 
					     memcmp(ifamap.address, ifamap.local, ifamap.address_len))) {
						/* p2p; address is peer and local is ours */
						ifamap.broadcast = ifamap.address;
						ifamap.broadcast_len = ifamap.address_len;
						ifamap.address = ifamap.local;
						ifamap.address_len = ifamap.local_len;
					}
					if (ifamap.address) {
						if (!build)
							dlen += NLMSG_ALIGN(ifamap.address_len);
						else {
							ifa->ifa_addr = (struct sockaddr *) data;
							memcpy(ifa->ifa_addr, ifamap.address, ifamap.address_len);
							data += NLMSG_ALIGN(ifamap.address_len);
						}
					}
				}
#endif
				if (!build) {
					icnt++;
				} else {
					ifl = ifa++;
				}
			}
		}
		if (!build) {
			if (icnt == 0 && (dlen + xlen == 0)) {
				if (ifap != NULL)
					*ifap = NULL;
				break;	/* cannot found any addresses */
			}
		}
	}

/* ---------------------------------- */
	/* Finalize */
	free_nlmsglist(nlmsg_list);
	nl_close(sd);
	return 0;
}

/* ---------------------------------------------------------------------- */
void ni_freeifaddrs(struct ni_ifaddrs *ifa)
{
	free(ifa);
}

