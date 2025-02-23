#ifndef _SSLOCAL_H
#define _SSLOCAL_H

#include "sspipe.h"

typedef struct {
    ssev_loop_t *loop;
    ssconfig_t *config;
    ssnet_t *net;
    int listen_fd;
} sslocal_t;

sslocal_t *sslocal_init(ssev_loop_t *loop, ssconfig_t *config);
void sslocal_free(sslocal_t *sslocal);

#endif /* SSLOCAL_H */