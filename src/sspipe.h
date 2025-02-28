#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "ss.h"
#include "sstcp.h"

typedef struct {
    sstcp_server_t* server;
    ssconfig_t* conf;
} sspipe_t;

sspipe_t* sspipe_init(ssconfig_t* conf);
int sspipe_start(sspipe_t* pipe);
void sspipe_free(sspipe_t* pipe);

#endif /* _SSPIPE_H */