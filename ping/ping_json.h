/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
 */

#ifndef IPUTILS_PING_JSON_H
#define IPUTILS_PING_JSON_H

#define PING_JSON_MAX 1000

enum PING_JSON_TYPE {
	PING_JSON_STR,
	PING_JSON_INT,
	PING_JSON_ARR,
	PING_JSON_UINT,
};

#include "ping/ping_output.h"

struct ping_json_buffer {
	size_t size;
	char object[PING_JSON_MAX];
};

void construct_json(struct ping_rts *rts, enum PING_JSON_TYPE ptype, char *key, ...);
void construct_json_error(struct ping_rts *rts, int errnum, char *errmsg);
void construct_json_statistics(struct ping_rts *rts, struct timespec tv, char *rttmin, char *rttavg, char *rttmax, char *rttmdev);
void construct_json_statistics_flood(struct ping_rts *rts, char *ipg, char *ewma);
void print_json_packet(struct ping_rts *rts);
void print_json_statistics(struct ping_rts *rts);

#endif /* IPUTILS_PING_JSON_H */
