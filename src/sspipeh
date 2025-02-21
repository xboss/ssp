#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "pconn.h"
#include "ssev.h"

typedef struct sspipe_s sspipe_t;

/* typedef int (*pipe_recv_cb_t)(sspipe_t* pipe, int fd, const char* buf, int len); */
typedef int (*pipe_accept_cb_t)(sspipe_t* pipe, int fd);

sspipe_t* sspipe_init(ssev_loop_t* loop, int read_buf_size, const char* listen_ip, unsigned short listen_port,
                      const char* key, /* pipe_recv_cb_t on_pipe_recv, */ pipe_accept_cb_t on_pipe_accept);
void sspipe_free(sspipe_t* pipe);

void sspipe_close_conn(sspipe_t* pipe, int fd);
int sspipe_connect(sspipe_t* pipe, const char* ip, unsigned short port, int cp_fd, int is_secret/* , int is_packet */);
int sspipe_send(sspipe_t* pipe, int fd, const char* buf, int len);

#endif /* _SSPIPE_H */