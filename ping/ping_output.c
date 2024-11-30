// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024-2025 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
 * Copyright (c) 2014-2024 Iputils project
 * Copyright (c) 1989-2006 The Regents of the University of California
 */

#include "ping.h"
#include <stdarg.h>
#include <stdbool.h>

void ping_print_int(struct ping_rts *rts, char *msg, char *json_key, int json_val)
{
	if (rts->opt_json)
		construct_json(rts, PING_JSON_INT, json_key, json_val);
	else
		printf(msg, json_val);
}

void ping_print_uint(struct ping_rts *rts, char *msg, char *json_key, unsigned int json_val)
{
	if (rts->opt_json)
		construct_json(rts, PING_JSON_UINT, json_key, json_val);
	else
		printf(msg, json_val);
}

void ping_print_str(struct ping_rts *rts, char *msg, char *json_key, char *json_val)
{
	if (rts->opt_json)
		construct_json(rts, PING_JSON_STR, json_key, json_val);
	else
		printf(msg, json_val);
}

inline void ping_print_version(struct ping_rts *rts)
{
	if (rts->opt_json) {
		construct_json(rts, PING_JSON_STR, "version", PACKAGE_VERSION);
		print_json_packet(rts);
	} else {
		printf(IPUTILS_VERSION("ping"));
		print_config();
	}
}

inline void ping_print_error_packet(struct ping_rts *rts, char *address, uint8_t sequence)
{
	if (!rts->opt_json)
		printf(_("From %s icmp_seq=%u "), address, sequence);
}

inline void ping_print_error_parse(struct ping_rts *rts, char *reason)
{
	if (!rts->opt_json)
		printf(_(" parse error (%s)"), reason);
	construct_json(rts, PING_JSON_STR, "error", reason);
}

inline void ping_print_error_qtype(struct ping_rts *rts, uint32_t val)
{
	if (!rts->opt_json)
		printf(_(" unknown qtype(0x%02x)"), val);
	construct_json(rts, PING_JSON_STR, "error", "unknown qtype");
}

inline void ping_print_truncated(struct ping_rts *rts)
{
	if (rts->opt_json) {
		construct_json(rts, PING_JSON_STR, "info", "truncated");
		return;
	}

	printf(_(" (truncated)"));
	if (rts->ni.subject_type == IPUTILS_NI_ICMP6_SUBJ_IPV4)
		putchar('\n');
}

inline void ping_print_packet(struct ping_rts *rts)
{
	if (!rts->opt_json) {
		char *source;
		char *target;

		if (rts->ni.subject_type == IPUTILS_NI_ICMP6_SUBJ_IPV6) {
			source = pr_addr(rts, &rts->source6, sizeof(rts->source6));
			target = pr_raw_addr(rts, &rts->whereto6, sizeof(rts->whereto6));
		} else {
			source = inet_ntoa(rts->source.sin_addr);
			target = inet_ntoa(rts->whereto.sin_addr);
		}

		printf(_("PING %s (%s) "), rts->hostname, target);

		if (rts->ni.subject_type == IPUTILS_NI_ICMP6_SUBJ_IPV6 && rts->flowlabel)
			printf(_(", flow 0x%05x, "), (unsigned int)ntohl(rts->flowlabel));

		if (rts->device || rts->opt_strictsource) {
			int saved_opt_numeric = rts->opt_numeric;

			rts->opt_numeric = 1;
			rts->opt_numeric = saved_opt_numeric;

			printf(_("from %s %s: "), source, rts->device ? rts->device : "");
		}

		if (rts->ni.subject_type == IPUTILS_NI_ICMP6_SUBJ_IPV6)
			printf(_("%d data bytes\n"), rts->datalen);
		else
			printf(_("%d(%d) bytes of data.\n"), rts->datalen, rts->datalen + 8 + rts->optlen + 20);
	}
}

static long llsqrt(long long a)
{
	long long prev = LLONG_MAX;
	long long x = a;

	if (x > 0) {
		while (x < prev) {
			prev = x;
			x = (x + (a / x)) / 2;
		}
	}

	return (long)x;
}

inline void ping_print_statistics(struct ping_rts *rts, struct timespec tv)
{
	double tmdev;
	char rttmin[30];
	char rttavg[30];
	char rttmax[30];
	char rttmdev[30];
	long long tmvar;

	long total = rts->nreceived + rts->nrepeats;
	long tmavg = rts->tsum / total;

	if (rts->tsum < INT_MAX)
		/* This slightly clumsy computation order is important to avoid
		 * integer rounding errors for small ping times.
		 */
		tmvar = (rts->tsum2 - ((rts->tsum * rts->tsum) / total)) / total;
	else
		tmvar = (rts->tsum2 / total) - (tmavg * tmavg);

	tmdev = llsqrt(tmvar);

	sprintf(rttmin, "%ld.%03ld", (long)rts->tmin / 1000, (long)rts->tmin % 1000);
	sprintf(rttavg, "%lu.%03ld", (unsigned long)(tmavg / 1000), (long)(tmavg % 1000));
	sprintf(rttmax, "%ld.%03ld", (long)rts->tmax / 1000, (long)rts->tmax % 1000);
	sprintf(rttmdev, "%ld.%03ld", (long)tmdev / 1000, (long)tmdev % 1000);

	if (!rts->opt_json)
		printf(_("rtt min/avg/max/mdev = %s/%s/%s/%s ms"),
			rttmin, rttavg, rttmax, rttmdev);

	construct_json_statistics(rts, tv, rttmin, rttavg, rttmax, rttmdev);
}

inline void ping_print_finish(struct ping_rts *rts)
{
	bool comma = 0;

	struct timespec tv = rts->cur_time;

	tssub(&tv, &rts->start_time);

	ping_finish_line(rts);

	if (!rts->opt_json) {
		printf(_("--- %s ping statistics ---\n"), rts->hostname);
		printf(_("%ld packets transmitted, "), rts->ntransmitted);
		printf(_("%ld received"), rts->nreceived);
		if (rts->nrepeats)
			printf(_(", +%ld duplicates"), rts->nrepeats);
		if (rts->nchecksum)
			printf(_(", +%ld corrupted"), rts->nchecksum);
		if (rts->nerrors)
			printf(_(", +%ld errors"), rts->nerrors);

		if (rts->ntransmitted) {
#ifdef USE_IDN
			setlocale(LC_ALL, "C");
#endif
			printf(_(", %g%% packet loss"),
			(float)((((long long)(rts->ntransmitted - rts->nreceived)) * 100.0) / rts->ntransmitted));
			printf(_(", time %llums"), (unsigned long long)(1000 * tv.tv_sec + (tv.tv_nsec + 500000) / 1000000));
		}

		putchar('\n');
	}

	if (rts->nreceived && rts->timing) {
		ping_print_statistics(rts, tv);
		comma = 1;
	}
	if (rts->pipesize > 1 && !rts->opt_json) {
		if (comma == 1)
			printf(", ");
		printf(_("pipe %d"), rts->pipesize);
		comma = 1;
	}

	if (rts->nreceived && (!rts->interval || rts->opt_flood || rts->opt_adaptive) && rts->ntransmitted > 1) {
		int ipg = (1000000 * (long long)tv.tv_sec + tv.tv_nsec / 1000) / (rts->ntransmitted - 1);

		char ipgout[30];
		char ewmaout[30];

		sprintf(ipgout, "%d.%03d", ipg / 1000, ipg % 1000);
		sprintf(ewmaout, "%d.%03d", rts->rtt / 8000, (rts->rtt / 8) % 1000);

		if (!rts->opt_json) {
			if (comma == 1)
				printf(", ");
			printf(_("ipg/ewma %s/%s ms"), ipgout, ewmaout);
		}

		construct_json_statistics_flood(rts, ipgout, ewmaout);
	}

	print_json_statistics(rts);
}

inline void ping_finish_line(struct ping_rts *rts)
{
	if (!rts->opt_json) {
		putchar('\n');
		fflush(stdout);
	}
}

void ping_error(struct ping_rts *rts, int status, int errnum, char *format, ...)
{
	char msg[50];

	va_list ap;

	va_start(ap, *format);

	vsnprintf(msg, sizeof(msg), format, ap);

	if (rts->opt_json) {
		construct_json_error(rts, errnum, msg);
		if (status > 0)
			exit(status);
	} else {
		error(status, errnum, "%s", msg);
	}
}
