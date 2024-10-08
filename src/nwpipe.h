#ifndef _NWPIPE_H
#define _NWPIPE_H

#include "ssev.h"

#define NWPIPE_CONN_TYPE_FR 1
#define NWPIPE_CONN_TYPE_BK 2
#define NWPIPE_CONN_ST_OFF 1
#define NWPIPE_CONN_ST_READY 2
#define NWPIPE_CONN_ST_ON 3

typedef struct nwpipe_s nwpipe_t;

typedef int (*pipe_recv_cb_t)(nwpipe_t *pipe, int fd, const char *buf, int len);
typedef int (*pipe_accept_cb_t)(nwpipe_t *pipe, int fd);

nwpipe_t *nwpipe_init(ssev_loop_t *loop, int read_buf_size, const char *listen_ip, unsigned short listen_port,
                      pipe_recv_cb_t on_pipe_recv, pipe_accept_cb_t on_pipe_accept);
void nwpipe_free(nwpipe_t *pipe);

void nwpipe_close_conn(nwpipe_t *pipe, int fd);
int nwpipe_connect(nwpipe_t *pipe, const char *ip, unsigned short port, int cp_fd, int is_secret, int is_packet);
int nwpipe_send(nwpipe_t *pipe, int fd, const char *buf, int len);

int nwpipe_get_couple_fd(nwpipe_t *pipe, int fd);
int nwpipe_is_conn_secret(nwpipe_t *pipe, int fd);
void nwpipe_set_conn_secret(nwpipe_t *pipe, int fd, int is_secret);
void nwpipe_set_conn_packet(nwpipe_t *pipe, int fd, int is_packet);
void nwpipe_set_conn_ex(nwpipe_t *pipe, int fd, int ex);
int nwpipe_get_conn_ex(nwpipe_t *pipe, int fd);
int nwpipe_get_conn_type(nwpipe_t *pipe, int fd);
int nwpipe_get_conn_status(nwpipe_t *pipe, int fd);

#endif /* NWPIPE_H */