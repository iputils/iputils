/*
 * Copyright (c) 1983 Regents of the University of California.
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

/*
 * Trivial file transfer protocol server.
 *
 * This version includes many modifications by Jim Guyton <guyton@rand-unix>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "iputils_common.h"
#include "tftp.h"

enum {
	MAXARG = 1,
	TIMEOUT = 5
};

struct errmsg {
	int e_code;
	char const *e_msg;
} errmsgs[] = {
	{EUNDEF, "Undefined error code"},
	{ENOTFOUND, "File not found"},
	{EACCESS, "Access violation"},
	{ENOSPACE, "Disk full or allocation exceeded"},
	{EBADOP, "Illegal TFTP operation"},
	{EBADID, "Unknown transfer ID"},
	{EEXISTS, "File already exists"},
	{ENOUSER, "No such user"},
	{-1, 0}
};

struct run_state;

struct formats {
	char *f_mode;
	int (*f_validate)(struct run_state *ctl, char *filename, int mode);
	void (*f_send)(struct run_state *ctl, struct formats *);
	void (*f_recv)(struct run_state *ctl, struct formats *);
	int f_convert;
};

struct run_state {
	int peer;
	int rexmtval;
	int maxtimeout;
	char buf[PKTSIZE];
	char ackbuf[PKTSIZE];
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} from;
	struct formats formats[3];
	socklen_t fromlen;
	int confirmed;
	int timeout;
	jmp_buf timeoutbuf;
	char *dirs[MAXARG + 1];
	FILE *file;
};
struct run_state *global_ctl;

/*
 * All includes, definitions, struct declarations, and global variables are above.  After
 * this comment all you can find is functions.
 */

/*
 * Send a nak packet (error message).  Error code passed in is one of the standard TFTP
 * codes, or a UNIX errno offset by 100.
 */
void nak(struct run_state *ctl, uint16_t error)
{
	struct tftphdr *tp;
	ssize_t length;
	struct errmsg *pe;

	tp = (struct tftphdr *)ctl->buf;
	tp->th_opcode = htons((uint16_t)ERROR);
	tp->th_code = htons(error);
	for (pe = errmsgs; pe->e_code >= 0; pe++)
		if (pe->e_code == error)
			break;
	if (pe->e_code < 0) {
		pe->e_msg = strerror(error - 100);
		tp->th_code = htons((uint16_t)EUNDEF);	/* set 'undef' errorcode */
	}
	length = strlen(pe->e_msg) + 1;	/* plus terminating null */
	memcpy(tp->th_msg, pe->e_msg, length);
	length += sizeof(tp->th_opcode) + sizeof(tp->th_code);
	if (send(ctl->peer, ctl->buf, length, 0) != length)
		syslog(LOG_ERR, "nak: %s\n", strerror(errno));
}

/*
 * Handle initial connection protocol.
 */
void tftp(struct run_state *ctl, struct tftphdr *tp, int size)
{
	char *cp;
	int first = 1, ecode;
	struct formats *pf;
	char *filename, *mode = NULL;

	filename = cp = tp->th_stuff;
 again:
	while (cp < ctl->buf + size) {
		if (*cp == '\0')
			break;
		cp++;
	}
	if (*cp != '\0') {
		nak(ctl, EBADOP);
		exit(1);
	}
	if (first) {
		mode = ++cp;
		first = 0;
		goto again;
	}
	for (cp = mode; *cp; cp++)
		if (isupper(*cp))
			*cp = tolower(*cp);
	for (pf = ctl->formats; pf->f_mode; pf++)
		if (strcmp(pf->f_mode, mode) == 0)
			break;
	if (pf->f_mode == 0) {
		nak(ctl, EBADOP);
		exit(1);
	}
	ecode = (*pf->f_validate) (ctl, filename, tp->th_opcode);
	if (ecode) {
		nak(ctl, ecode);
		exit(1);
	}
	if (tp->th_opcode == WRQ)
		(*pf->f_recv) (ctl, pf);
	else
		(*pf->f_send) (ctl, pf);
	exit(0);
}

/*
 * Validate file access.  Since we have no uid or gid, for now require file to exist and
 * be publicly readable/writable.

 * If we were invoked with arguments from inetd then the file must also be in one of the
 * given directory prefixes.  Note also, full path name must be given as we have no login
 * directory.
 */
int validate_access(struct run_state *ctl, char *filename, int mode)
{
	struct stat stbuf;
	int fd;
	char *cp;
	char fnamebuf[1024 + 512];

	for (cp = filename; *cp; cp++) {
		if (*cp == '.' && (cp == filename || strncmp(cp - 1, "/../", 4) == 0)) {
			syslog(LOG_ERR, "bad path %s", filename);
			return EACCESS;
		}
	}

	if (*filename == '/')
		filename++;

	if (!*ctl->dirs) {
		syslog(LOG_ERR, "no dirs");
		return EACCESS;
	}
	snprintf(fnamebuf, sizeof(fnamebuf) - 1, "%s/%s", *ctl->dirs, filename);
	filename = fnamebuf;

	if (stat(filename, &stbuf) < 0) {
		syslog(LOG_ERR, "stat %s : %s", filename, strerror(errno));
		return (errno == ENOENT ? ENOTFOUND : EACCESS);
	}
	if (mode == RRQ) {
		if ((stbuf.st_mode & (S_IREAD >> 6)) == 0) {
			syslog(LOG_ERR, "not readable %s", filename);
			return EACCESS;
		}
	} else {
		if ((stbuf.st_mode & (S_IWRITE >> 6)) == 0) {
			syslog(LOG_ERR, "not writable %s", filename);
			return EACCESS;
		}
	}
	fd = open(filename, mode == RRQ ? 0 : 1);
	if (fd < 0) {
		syslog(LOG_ERR, "cannot open %s: %s", filename, strerror(errno));
		return (errno + 100);
	}
	ctl->file = fdopen(fd, (mode == RRQ) ? "r" : "w");
	if (ctl->file == NULL) {
		return (errno + 100);
	}
	return 0;
}

void timer(int signo __attribute__((__unused__)))
{
	global_ctl->confirmed = 0;
	global_ctl->timeout += global_ctl->rexmtval;
	if (global_ctl->timeout >= global_ctl->maxtimeout)
		exit(1);
	longjmp(global_ctl->timeoutbuf, 1);
}

/*
 * Send the requested file.
 */
void sendfile(struct run_state *ctl, struct formats *pf)
{
	struct tftphdr *dp;
	struct tftphdr *ap;	/* ack packet */
	volatile uint16_t block = 1;
	ssize_t size, n;

	ctl->confirmed = 0;
	signal(SIGALRM, timer);
	dp = r_init();
	ap = (struct tftphdr *)ctl->ackbuf;
	do {
		size = readit(ctl->file, &dp, pf->f_convert);
		if (size < 0) {
			nak(ctl, errno + 100);
			goto abort;
		}
		dp->th_opcode = htons((uint16_t)DATA);
		dp->th_block = htons(block);
		ctl->timeout = 0;
		setjmp(ctl->timeoutbuf);

 send_data:
		if (send(ctl->peer, dp, size + 4, ctl->confirmed) != size + 4) {
			syslog(LOG_ERR, "tftpd: write: %s\n", strerror(errno));
			goto abort;
		}
		ctl->confirmed = 0;
		read_ahead(ctl->file, pf->f_convert);
		for (;;) {
			alarm(ctl->rexmtval);	/* read the ack */
			n = recv(ctl->peer, ctl->ackbuf, sizeof(ctl->ackbuf), 0);
			alarm(0);
			if (n < 0) {
				syslog(LOG_ERR, "tftpd: read: %s\n", strerror(errno));
				goto abort;
			}
			ap->th_opcode = ntohs((uint16_t)ap->th_opcode);
			ap->th_block = ntohs((uint16_t)ap->th_block);

			if (ap->th_opcode == ERROR)
				goto abort;

			if (ap->th_opcode == ACK) {
				if (ap->th_block == block) {
					ctl->confirmed = MSG_CONFIRM;
					break;
				}
				/* Re-synchronize with the other side */
				synchnet(ctl->peer);
				if (ap->th_block == (block - 1)) {
					goto send_data;
				}
			}

		}
		block++;
	} while (size == SEGSIZE);
 abort:
	fclose(ctl->file);
}

void justquit(int signo __attribute__((__unused__)))
{
	exit(0);
}

/*
 * Receive a file.
 */
void recvfile(struct run_state *ctl, struct formats *pf)
{
	struct tftphdr *dp;
	struct tftphdr *ap;	/* ack buffer */
	volatile uint16_t block = 0;
	ssize_t n, size;

	ctl->confirmed = 0;
	signal(SIGALRM, timer);
	dp = w_init();
	ap = (struct tftphdr *)ctl->ackbuf;
	do {
		ctl->timeout = 0;
		ap->th_opcode = htons((uint16_t)ACK);
		ap->th_block = htons(block);
		block++;
		setjmp(ctl->timeoutbuf);
 send_ack:
		if (send(ctl->peer, ctl->ackbuf, 4, ctl->confirmed) != 4) {
			syslog(LOG_ERR, "tftpd: write: %s\n", strerror(errno));
			goto abort;
		}
		ctl->confirmed = 0;
		write_behind(ctl->file, pf->f_convert);
		for (;;) {
			alarm(ctl->rexmtval);
			n = recv(ctl->peer, dp, PKTSIZE, 0);
			alarm(0);
			if (n < 0) {	/* really? */
				syslog(LOG_ERR, "tftpd: read: %s\n", strerror(errno));
				goto abort;
			}
			dp->th_opcode = ntohs((uint16_t)dp->th_opcode);
			dp->th_block = ntohs((uint16_t)dp->th_block);
			if (dp->th_opcode == ERROR)
				goto abort;
			if (dp->th_opcode == DATA) {
				if (dp->th_block == block) {
					ctl->confirmed = MSG_CONFIRM;
					break;	/* normal */
				}
				/* Re-synchronize with the other side */
				synchnet(ctl->peer);
				if (dp->th_block == (block - 1))
					goto send_ack;	/* rexmit */
			}
		}
		/* size = write(file, dp->th_data, n - 4); */
		size = writeit(ctl->file, &dp, n - 4, pf->f_convert);
		if (size != (n - 4)) {	/* ahem */
			if (size < 0)
				nak(ctl, errno + 100);
			else
				nak(ctl, ENOSPACE);
			goto abort;
		}
	} while (size == SEGSIZE);
	write_behind(ctl->file, pf->f_convert);
	if (close_stream(ctl->file))
		syslog(LOG_ERR, "tftpd: write error: %s\n",  strerror(errno));
	fclose(ctl->file);		/* close data file */

	ap->th_opcode = htons((uint16_t)ACK);	/* send the "final" ack */
	ap->th_block = htons(block);
	send(ctl->peer, ctl->ackbuf, 4, ctl->confirmed);

	signal(SIGALRM, justquit);	/* just quit on timeout */
	alarm(ctl->rexmtval);
	n = recv(ctl->peer, ctl->buf, sizeof(ctl->buf), 0);	/* normally times out and quits */
	alarm(0);
	if (n >= 4 &&			/* if read some data */
	    dp->th_opcode == DATA &&	/* and got a data block */
	    block == dp->th_block) {	/* then my last ack was lost */
		send(ctl->peer, ctl->ackbuf, 4, 0);	/* resend final ack */
	}
 abort:
	return;
}

int tftpd_inetd(struct run_state *ctl)
{
	struct tftphdr *tp;
	int on = 1;
	ssize_t n;

	openlog("tftpd", LOG_PID, LOG_DAEMON);

	/* Sanity. If parent forgot to setuid() on us. */
	if (geteuid() == 0) {
		/* Drop all supplementary groups. No error checking is needed */
		setgroups(0, NULL);
		if (setgid(65534) || setuid(65534)) {
			syslog(LOG_ERR, "set*id failed: %s\n", strerror(errno));
			exit(1);
		}
	}

	if (ioctl(0, FIONBIO, &on) < 0) {
		syslog(LOG_ERR, "ioctl(FIONBIO): %s\n", strerror(errno));
		exit(1);
	}
	ctl->fromlen = sizeof(ctl->from);
	n = recvfrom(0, ctl->buf, sizeof(ctl->buf), 0,
		     (struct sockaddr *)&ctl->from, &ctl->fromlen);
	if (n < 0) {
		if (errno != EAGAIN)
			syslog(LOG_ERR, "recvfrom: %s\n", strerror(errno));
		exit(1);
	}
	/*
	 * Now that we have read the message out of the UDP socket, we fork and exit.
	 * Thus, inetd will go back to listening to the tftp port, and the next request
	 * to come in will start up a new instance of tftpd.
	 *
	 * We do this so that inetd can run tftpd in "wait" mode.  The problem with tftpd
	 * running in "nowait" mode is that inetd may get one or more successful
	 * "selects" on the tftp port before we do our receive, so more than one instance
	 * of tftpd may be started up.  Worse, if tftpd break before doing the above
	 * "recvfrom", inetd would spawn endless instances, clogging the system.
	 */
	{
		int pid = -1;
		int i;
		socklen_t j;

		for (i = 1; i < 20; i++) {
			pid = fork();
			if (0 <= pid)
				break;
			sleep(i);
			/*
			 * flush out to most recently sent request.
			 *
			 * This may drop some request, but those will be resent by the
			 * clients when they timeout.  The positive effect of this flush
			 * is to (try to) prevent more than one tftpd being started up to
			 * service a single request from a single client.
			 */
			j = sizeof ctl->from;
			i = recvfrom(0, ctl->buf, sizeof(ctl->buf), 0,
				     (struct sockaddr *)&ctl->from, &j);
			if (i > 0) {
				n = i;
				ctl->fromlen = j;
			}
		}
		if (pid < 0) {
			syslog(LOG_ERR, "fork: %s\n", strerror(errno));
			exit(1);
		}
		if (pid != 0)
			exit(0);
	}
	alarm(0);
	close(0);
	close(1);
	ctl->peer = socket(ctl->from.sa.sa_family, SOCK_DGRAM, 0);
	if (ctl->peer < 0) {
		syslog(LOG_ERR, "socket: %s\n", strerror(errno));
		exit(1);
	}
	if (connect(ctl->peer, (struct sockaddr *)&ctl->from, sizeof(ctl->from)) < 0) {
		syslog(LOG_ERR, "connect: %s\n", strerror(errno));
		exit(1);
	}
	tp = (struct tftphdr *)ctl->buf;
	tp->th_opcode = ntohs(tp->th_opcode);
	if (tp->th_opcode == RRQ || tp->th_opcode == WRQ)
		tftp(ctl, tp, n);
	return 1;
}

static void __attribute__((__noreturn__)) usage(void)
{
	printf("\nUsage:\n");
	printf(" %s [options] directory\n", program_invocation_short_name);
	printf("\nOptions:\n");
	printf(" -h, --help           display this help\n");
	printf(" -V, --version        display version\n");
	printf("\nFor more details see tftpd(8).\n");
	exit(EXIT_SUCCESS);
}

int main(int ac, char **av)
{
	struct run_state ctl = {
		.rexmtval = TIMEOUT,
		.maxtimeout = 5 * TIMEOUT,
		.formats = {
			{"netascii", validate_access, sendfile, recvfile, 1},
			{"octet", validate_access, sendfile, recvfile, 0}
		}
	};
	int c, n = 0;
	static const struct option longopts[] = {
		{"version", no_argument, NULL, 'V'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	global_ctl = &ctl;

	while ((c = getopt_long(ac, av, "Vh", longopts, NULL)) != -1)
		switch (c) {
		case 'V':
			printf(IPUTILS_VERSION("tftpd"));
			return EXIT_SUCCESS;
		case 'h':
			usage();
		default:
			fprintf(stderr,
				"Try '%s --help' for more information.\n",
				program_invocation_short_name);
			exit(1);
		}
	ac--;
	av++;
	while (ac-- > 0 && n < MAXARG)
		ctl.dirs[n++] = *av++;
	return tftpd_inetd(&ctl);
}
