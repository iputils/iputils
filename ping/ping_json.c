// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024-2025 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
 */

#include "ping.h"
#include <stdarg.h>

static inline void json_emergency(char *msg)
{
	error(1, 0, "%s", msg);
}

static inline void json_bufsize(struct ping_json_buffer *json_packet, int size)
{
	if (size < 0 || size >= PING_JSON_MAX)
		json_emergency(_("Overflow during JSON construction"));

	json_packet->size += size;
}

static void json_end_array(struct ping_json_buffer *json_packet)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "]"));
}

static void json_start_object(struct ping_json_buffer *json_packet)
{
	json_bufsize(json_packet, snprintf(json_packet->object, PING_JSON_MAX, "{"));
}

static void json_end_object(struct ping_json_buffer *json_packet)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "}"));
}

static void json_continue(struct ping_json_buffer *json_packet)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, ", "));
}

static void json_kv_str(struct ping_json_buffer *json_packet, char *key, char *val)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "\"%s\": \"%s\"", key, val));
}

static void json_kv_str_continue(struct ping_json_buffer *json_packet, char *key, char *val)
{
	json_kv_str(json_packet, key, val);
	json_continue(json_packet);
}

static void json_kv_int(struct ping_json_buffer *json_packet, char *key, int val)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "\"%s\": %d", key, val));
}

static void json_kv_uint(struct ping_json_buffer *json_packet, char *key, unsigned int val)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "\"%s\": %u", key, val));
}

static void json_kv_int_continue(struct ping_json_buffer *json_packet, char *key, int val)
{
	json_kv_int(json_packet, key, val);
	json_continue(json_packet);
}

/* so far only supports arrays of strings */
static void json_kv_array(struct ping_json_buffer *json_packet, char *key, va_list ap)
{
	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "\"%s\": [", key));

	char *val;
	int count = 0;

	while (1) {
		val = va_arg(ap, char *);

		if (!val)
			break;

		if (count > 0)
			json_continue(json_packet);

		json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "\"%s\"", val));

		count = count + 1;
	}

	json_end_array(json_packet);
}

static void json_kv_object(struct ping_json_buffer *json_packet, char *key, struct ping_json_buffer *json_val)
{
	json_end_object(json_val);

	json_bufsize(json_packet, snprintf(json_packet->object + json_packet->size, PING_JSON_MAX - json_packet->size, "\"%s\": %s", key, json_val->object));
}

void construct_json(struct ping_rts *rts, enum PING_JSON_TYPE ptype, char *key, ...)
{
	if (!rts->opt_json)
		return;

	char *val_str;
	int val_int;
	unsigned int val_uint;

	va_list ap;

	va_start(ap, *key);

	if (*rts->json_packet.object)
		json_continue(&rts->json_packet);
	else
		json_start_object(&rts->json_packet);

	switch (ptype) {
	case PING_JSON_ARR:
		json_kv_array(&rts->json_packet, key, ap);
		break;

	case PING_JSON_STR:
		val_str = va_arg(ap, char *);
		json_kv_str(&rts->json_packet, key, val_str);
		break;

	case PING_JSON_INT:
		val_int = va_arg(ap, int);
		json_kv_int(&rts->json_packet, key, val_int);
		break;

	case PING_JSON_UINT:
		val_uint = va_arg(ap, unsigned int);
		json_kv_uint(&rts->json_packet, key, val_uint);
		break;
	}

	va_end(ap);
}

void construct_json_statistics(struct ping_rts *rts, struct timespec tv, char *rttmin, char *rttavg, char *rttmax, char *rttmdev)
{
	if (!rts->opt_json)
		return;

	if (*rts->json_stats.object)
		json_continue(&rts->json_stats);
	else
		json_start_object(&rts->json_stats);

	json_kv_str_continue(&rts->json_stats, "host", rts->hostname);
	json_kv_int_continue(&rts->json_stats, "transmitted", rts->ntransmitted);
	json_kv_int_continue(&rts->json_stats, "received", rts->nreceived);
	json_kv_int_continue(&rts->json_stats, "duplicates", rts->nrepeats);
	json_kv_int_continue(&rts->json_stats, "corrupted", rts->nchecksum);
	json_kv_int_continue(&rts->json_stats, "errors", rts->nerrors);
	json_kv_int_continue(&rts->json_stats, "loss", (float)((((long long)(rts->ntransmitted - rts->nreceived)) * 100.0) / rts->ntransmitted));
	json_kv_int_continue(&rts->json_stats, "time", (unsigned long long)(1000 * tv.tv_sec + (tv.tv_nsec + 500000) / 1000000));

	struct ping_json_buffer json_rtt;

	json_rtt.size = 0;

	json_start_object(&json_rtt);
	json_kv_str_continue(&json_rtt, "min", rttmin);
	json_kv_str_continue(&json_rtt, "avg", rttavg);
	json_kv_str_continue(&json_rtt, "max", rttmax);
	json_kv_str(&json_rtt, "mdev", rttmdev);

	json_kv_object(&rts->json_stats, "rtt", &json_rtt);

	if (rts->pipesize > 1) {
		json_continue(&rts->json_stats);
		json_kv_int_continue(&rts->json_stats, "pipe", rts->pipesize);
	}
}

void construct_json_statistics_flood(struct ping_rts *rts, char *ipg, char *ewma)
{
	if (!rts->opt_json || !*rts->json_stats.object)
		return;

	// align with conditionals in finish()
	if (rts->nreceived && rts->timing && rts->pipesize < 2)
		json_continue(&rts->json_stats);

	json_kv_str_continue(&rts->json_stats, "ipg", ipg);
	json_kv_str(&rts->json_stats, "ewma", ewma);
}

void print_json_and_reset(struct ping_json_buffer *json_packet)
{
	printf("%s}\n", json_packet->object);
	fflush(stdout);
	*json_packet->object = '\0';
	json_packet->size = 0;
}

void print_json_packet(struct ping_rts *rts)
{
	if (rts->opt_json && *rts->json_packet.object)
		print_json_and_reset(&rts->json_packet);
}

void print_json_statistics(struct ping_rts *rts)
{
	if (rts->opt_json && *rts->json_stats.object) {
		printf("%s}\n", rts->json_stats.object);
		fflush(stdout);
		*rts->json_stats.object = '\0';
		rts->json_stats.size = 0;
	}
	if (!rts->opt_json)
		putchar('\n');
}

void construct_json_error(struct ping_rts *rts, int errnum, char *errmsg)
{
	if (errnum < 0)
		json_emergency("Unable to process errnum for JSON construction.");

	if (errmsg && errnum == 0)
		construct_json(rts, PING_JSON_STR, "error", errmsg);
	else if (!errmsg)
		construct_json(rts, PING_JSON_STR, "error", strerror(errnum));
	else
		construct_json(rts, PING_JSON_ARR, "error", errmsg, strerror(errnum));

	print_json_packet(rts);
}
