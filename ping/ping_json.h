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

#ifndef IPUTILS_PING_JSON_H
#define IPUTILS_PING_JSON_H

#define PING_JSON_NUL 0
#define PING_JSON_STR 1
#define PING_JSON_INT 2
#define PING_JSON_MAX 1000

/* extract first argument whilst staying C99 compliant */
#define _JSON_VALUE(value, ...) value
#define JSON_VALUE(...) _JSON_VALUE(__VA_ARGS__, NULL)
#define PRINT(msg, json_key, json_type, ...) \
	do { \
		if (rts->opt_json) \
			construct_json(rts, json_type, json_key, JSON_VALUE(__VA_ARGS__)); \
		else \
			printf(msg, __VA_ARGS__); \
	} while (0)
#define PRINT_INT(msg, json_key, ...) PRINT(msg, json_key, PING_JSON_INT, __VA_ARGS__)
#define PRINT_STR(msg, json_key, ...) PRINT(msg, json_key, PING_JSON_STR, __VA_ARGS__)

#define ERROR(status, errnum, error_type, json_type, ...) \
	do { \
		if (rts->opt_json) \
			error_json(rts, status, error_type, strerror(errnum), json_type, __VA_ARGS__); \
		else \
			error(status, errnum, error_type); \
	} while (0)

void construct_json(struct ping_rts *rts, int ptype, char *key, ...);
void construct_json_statistics(struct ping_rts *rts, struct timespec tv, char *rttmin, char *rttavg, char *rttmax, char *rttmdev);
void construct_json_statistics_flood(struct ping_rts *rts, char *ipg, char *ewma);
void print_json_packet(struct ping_rts *rts);
void print_json_statistics(struct ping_rts *rts);
void error_json(struct ping_rts *rts, int status, char *errtype, char *errmsg, int ptype, char *extrakey, ...);

#endif /* IPUTILS_PING_JSON_H */
