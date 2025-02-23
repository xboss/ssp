#ifndef _SSREMOTE_H
#define _SSREMOTE_H

#include "sspipe.h"

typedef struct {
    ssev_loop_t *loop;
    ssconfig_t *config;
    ssnet_t *net;
    int listen_fd;
} ssremote_t;

ssremote_t *ssremote_init(ssev_loop_t *loop, ssconfig_t *config);
void ssremote_free(ssremote_t *ssremote);

#endif /* SSREMOTE_H */