/*
 * Copyright (c) 2024 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "ping.h"
#include "stdarg.h"

void test_buflen(int have) {
	if (have < 0 || have >= PING_JSON_MAX) {
		error(1, 0, "Fatal error during JSON construction.");
	}
}

void json_start_object(char *part) {
	test_buflen(snprintf(part, PING_JSON_MAX, "{"));
}

void json_end_object(char *part) {
	size_t curlen = strlen(part);
	test_buflen(snprintf(part + curlen, PING_JSON_MAX - curlen, "}"));
}

void json_continue(char *part) {
	size_t curlen = strlen(part);
	test_buflen(snprintf(part + curlen, PING_JSON_MAX - curlen, ", "));
}

void json_kv_str(char *part, char *key, char *value) {
	size_t curlen = strlen(part);
	test_buflen(snprintf(part + curlen, PING_JSON_MAX - curlen, "\"%s\": \"%s\"", key, value));
}

void json_kv_str_continue(char *part, char *key, char *value) {
	json_kv_str(part, key, value);
	json_continue(part);
}

void json_kv_int(char *part, char *key, int value) {
	size_t curlen = strlen(part);
	test_buflen(snprintf(part + curlen, PING_JSON_MAX - curlen, "\"%s\": %d", key, value));
}

void json_kv_int_continue(char *part, char *key, int value) {
	json_kv_int(part, key, value);
	json_continue(part);
}

void json_kv_object(char *part, char *key, char *value) {
	json_end_object(value);
	size_t curlen = strlen(part);
	test_buflen(snprintf(part + curlen, PING_JSON_MAX - curlen, "\"%s\": %s", key, value));
}

void construct_json(struct ping_rts *rts, int ptype, char *key, ...) {
	if (!rts->opt_json) {
		return;
	}

	char * val_str;
	int val_int;
	
	va_list ap;
	va_start (ap, *key);

	if (*rts->json_packet) {
		json_continue(rts->json_packet);
	} else {
		json_start_object(rts->json_packet);
	}

	switch (ptype) {
		case PING_JSON_STR:
			val_str = va_arg (ap, char *);
			json_kv_str(rts->json_packet, key, val_str);
			break;

		case PING_JSON_INT:
			val_int = va_arg (ap, int);
			json_kv_int(rts->json_packet, key, val_int);
			break;
	}

	va_end (ap);
}

void construct_json_statistics(struct ping_rts *rts, struct timespec tv, char *rttmin, char *rttavg, char *rttmax, char *rttmdev) {
	if (!rts->opt_json) {
		return;
	}

	if (*rts->json_stats) {
		json_continue(rts->json_stats);
	} else {
		json_start_object(rts->json_stats);
	}

	json_kv_str_continue(rts->json_stats, "host", rts->hostname);
	json_kv_int_continue(rts->json_stats, "transmitted", rts->ntransmitted);
	json_kv_int_continue(rts->json_stats, "received", rts->nreceived);
	json_kv_int_continue(rts->json_stats, "duplicates", rts->nrepeats);
	json_kv_int_continue(rts->json_stats, "corrupted", rts->nchecksum);
	json_kv_int_continue(rts->json_stats, "errors", rts->nerrors);
	json_kv_int_continue(rts->json_stats, "loss", (float)((((long long)(rts->ntransmitted - rts->nreceived)) * 100.0) / rts->ntransmitted));
	json_kv_int_continue(rts->json_stats, "time", (unsigned long long)(1000 * tv.tv_sec + (tv.tv_nsec + 500000) / 1000000));

	char json_rtt[PING_JSON_MAX];
	json_start_object(json_rtt);
	json_kv_str_continue(json_rtt, "min", rttmin);
	json_kv_str_continue(json_rtt, "avg", rttavg);
	json_kv_str_continue(json_rtt, "max", rttmax);
	json_kv_str(json_rtt, "mdev", rttmdev);

	json_kv_object(rts->json_stats, "rtt", json_rtt);

	if (rts->pipesize > 1) {
		json_kv_int(rts->json_stats, "pipe", rts->pipesize);
	}
}

void construct_json_statistics_flood(struct ping_rts *rts, char *ipg, char *ewma) {
	if (!rts->opt_json || !*rts->json_stats) {
		return;
	}

	json_kv_str(rts->json_stats, "ipg", ipg);
	json_kv_str(rts->json_stats, "ewma", ewma);
}

void print_json_and_reset(char *part) {
	printf("%s}\n", part);
	fflush(stdout);
	*part = '\0';
}

void print_json_packet(struct ping_rts *rts) {
	if (rts->opt_json && *rts->json_packet)
		print_json_and_reset(rts->json_packet);
}

void print_json_statistics(struct ping_rts *rts) {
	if (rts->opt_json && *rts->json_stats) {
		printf("%s}\n", rts->json_stats);
		fflush(stdout);
	}
}

void error_json(struct ping_rts *rts, int status, char *errtype, char *errmsg, int ptype, char *extrakey, ...) { 
	if (!rts->opt_json) {
		return;
	}

	char * extraval_str;
	int extraval_int;

	char json_error[PING_JSON_MAX];
	json_start_object(json_error);

	if (*rts->json_packet) {
		json_continue(rts->json_packet);
	} else {
		json_start_object(rts->json_packet);
	}

	va_list ap;
	va_start (ap, *extrakey);

	json_kv_str_continue(json_error, "type", errtype);
	json_kv_str_continue(json_error, "error", errmsg);
	json_kv_int(json_error, "status", status);

	switch (ptype) {
		case PING_JSON_NUL:
			break;

		case PING_JSON_STR:
			extraval_str = va_arg (ap, char *);
			json_kv_str(json_error, extrakey, extraval_str);
			break;

		case PING_JSON_INT:
			extraval_int = va_arg (ap, int);
			json_kv_int(json_error, extrakey, extraval_int);
			break;
	}

	va_end (ap);

	json_kv_object(rts->json_packet, "error", json_error);

	print_json_packet(rts);

	if (status > 0)
		exit(status);
}
