#ifndef _SOCKS_H
#define _SOCKS_H

#include "sspipe.h"

int on_socks_recv(sspipe_t *pipe, int fd, const char *buf, int len);
int on_socks_accept(sspipe_t *pipe, int fd);

#endif /* SOCKS_H */