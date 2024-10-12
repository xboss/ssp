#ifndef _NWPIPE_H
#define _NWPIPE_H

#include "pconn.h"
#include "ssev.h"

typedef struct nwpipe_s nwpipe_t;

typedef int (*pipe_recv_cb_t)(nwpipe_t *pipe, int fd, const char *buf, int len);
typedef int (*pipe_accept_cb_t)(nwpipe_t *pipe, int fd);

nwpipe_t *nwpipe_init(ssev_loop_t *loop, int read_buf_size, const char *listen_ip, unsigned short listen_port,
                      pipe_recv_cb_t on_pipe_recv, pipe_accept_cb_t on_pipe_accept);
void nwpipe_free(nwpipe_t *pipe);

void nwpipe_close_conn(nwpipe_t *pipe, int fd);
int nwpipe_connect(nwpipe_t *pipe, const char *ip, unsigned short port, int cp_fd, int is_secret, int is_packet);
int nwpipe_send(nwpipe_t *pipe, int fd, const char *buf, int len);

#endif /* NWPIPE_H */