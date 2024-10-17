#ifndef _SSNET_H
#define _SSNET_H

#include <arpa/inet.h>

#include "ssev.h"

typedef struct ssnet_s ssnet_t;

typedef int (*ssnet_recv_cb_t)(ssnet_t *net, int fd, const char *buf, int len, struct sockaddr *addr);
typedef int (*ssnet_close_cb_t)(ssnet_t *net, int fd);
typedef int (*ssnet_accept_cb_t)(ssnet_t *net, int fd);
typedef int (*ssnet_writable_cb_t)(ssnet_t *net, int fd);

ssnet_t *ssnet_init(ssev_loop_t *loop, int read_buf_size);
void ssnet_free(ssnet_t *net);

void *ssnet_get_userdata(ssnet_t *net);
int ssnet_set_userdata(ssnet_t *net, void *userdata);
int ssnet_set_recv_cb(ssnet_t *net, ssnet_recv_cb_t on_recv);
int ssnet_set_close_cb(ssnet_t *net, ssnet_close_cb_t on_close);
int ssnet_set_writable_cb(ssnet_t *net, ssnet_writable_cb_t on_writable);

/* -------- TCP -------- */
/**
 * @return >0:ok; 0:colsed; -1:pending; -2:error
 */
int ssnet_tcp_send(ssnet_t *net, int fd, const char *buf, int len);
void ssnet_tcp_close(ssnet_t *net, int fd);
int ssnet_tcp_init_server(ssnet_t *net, const char *bind_ip, unsigned short port, ssnet_accept_cb_t on_accept);
void ssnet_tcp_stop_server(ssnet_t *net, int listen_fd);
int ssnet_tcp_connect(ssnet_t *net, const char *ip, unsigned short port);

/* -------- UDP -------- */
int ssnet_udp_init(ssnet_t *net, const char *ip, unsigned short port, int is_bind);
void ssnet_udp_free(ssnet_t *net, int fd);
int ssnet_udp_send(ssnet_t *net, int fd, const char *buf, int len, const struct sockaddr *addr);

#endif /* _SSNET_H */