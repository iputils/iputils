#ifndef PING6_COMMON_H
# define PING6_COMMON_H

int ping6_main(int argc, char *argv[], socket_st *sockets);
void ping6_usage(unsigned from_ping);

int ping6_send_probe(socket_st *sockets, void *packet, unsigned packet_size);
int ping6_receive_error_msg(socket_st *sockets);
int ping6_parse_reply(struct msghdr *msg, int len, void *addr, struct timeval *);
void ping6_install_filter(socket_st *sockets);

extern ping_func_set_st ping6_func_set;

#endif
