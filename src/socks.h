#ifndef _SOCKS_H
#define _SOCKS_H

#include "nwpipe.h"

int on_socks_recv(nwpipe_t *pipe, int fd, const char *buf, int len);
int on_socks_accept(nwpipe_t *pipe, int fd);

#endif /* SOCKS_H */