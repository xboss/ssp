#ifndef _SOCKS_H
#define _SOCKS_H

#include "sspipe.h"

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

int on_socks_recv(sspipe_t *pipe, int fd, const char *buf, int len);
int on_socks_accept(sspipe_t *pipe, int fd);

#endif /* SOCKS_H */