#ifndef _NETWORK_H
#define _NETWORK_H

#include "ssev.h"

typedef struct network_s network_t;

typedef int (*nw_recv_cb_t)(network_t *nw, int fd, const char *buf, int len);
typedef int (*nw_close_cb_t)(network_t *nw, int fd);
typedef int (*nw_accept_cb_t)(network_t *nw, int fd);
typedef int (*nw_writable_cb_t)(network_t *nw, int fd);

network_t *nw_init(ssev_loop_t *loop, int read_buf_size);
void nw_free(network_t *nw);

/**
 * @return >0:ok; 0:colsed; -1:pending; -2:error
 */
int nw_tcp_send(network_t *nw, int fd, const char *buf, int len);
void nw_tcp_close(network_t *nw, int fd);

int nw_tcp_init_server(network_t *nw, const char *bind_ip, unsigned short port, nw_accept_cb_t on_accept);
void nw_tcp_stop_server(network_t *nw, int listen_fd);

int nw_tcp_connect(network_t *nw, const char *ip, unsigned short port);

void *nw_get_userdata(network_t *nw);
int nw_set_userdata(network_t *nw, void *userdata);
int nw_set_recv_cb(network_t *nw, nw_recv_cb_t on_recv);
int nw_set_close_cb(network_t *nw, nw_close_cb_t on_close);
int nw_set_writable_cb(network_t *nw, nw_writable_cb_t on_writable);

#endif /* NETWORK_H */