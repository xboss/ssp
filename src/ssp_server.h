#ifndef _SSP_SERVER_H
#define _SSP_SERVER_H

#include "ssp.h"
#include "sspipe.h"

typedef struct {
    ssp_config_t* conf;
    sspipe_ctx_t* sspipe_ctx;
    int listen_fd;
    char *recv_buf;
    ev_io *accept_watcher;
    struct ev_loop *loop;
} ssp_server_t;

ssp_server_t* ssp_server_init(struct ev_loop *loop, ssp_config_t* conf);
int ssp_server_start(ssp_server_t* ssp_server);
void ssp_server_stop(ssp_server_t* ssp_server);
void ssp_server_free(ssp_server_t* ssp_server);
void ssp_monitor(ssp_server_t* ssp_server);

#endif /* _SSP_SERVER_H */