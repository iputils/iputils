/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2025 Georg Pfuetzenreuter <mail+ip@georg-pfuetzenreuter.net>
 */

void ping_print_uint(struct ping_rts *rts, char *msg, char *json_key, unsigned int json_val);
void ping_print_int(struct ping_rts *rts, char *msg, char *json_key, int json_val);
void ping_print_str(struct ping_rts *rts, char *msg, char *json_key, char *json_val);
void ping_print_version(struct ping_rts *rts);
void ping_print_error_packet(struct ping_rts *rts, char *address, uint8_t sequence);
void ping_print_error_parse(struct ping_rts *rts, char *reason);
void ping_print_error_qtype(struct ping_rts *rts, uint32_t val);
void ping_print_truncated(struct ping_rts *rts);
void ping_print_packet(struct ping_rts *rts);
void ping_print_error_parse(struct ping_rts *rts, char *reason);
void ping_print_finish(struct ping_rts *rts);
void ping_print_statistics(struct ping_rts *rts, struct timespec tv);
void ping_finish_line(struct ping_rts *rts);

void ping_error(struct ping_rts *rts, int status, int errnum, char *format, ...);
