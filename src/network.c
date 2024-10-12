
#include "network.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef DEBUG
#include "debug.h"
#endif

#ifndef _LOG
#define _LOG(fmt, ...)
#endif

#define NW_OK (0)
#define NW_ERR (-1)

#define LISTEN_BACKLOG (128)
#define EPOLL_SIZE (256)
#define MAX_EVENTS (128)
#define DEF_READ_BUF_SIZE (2048)
#define DEF_EV_TIMEOUT (1000)

#ifndef _ALLOC
#define _ALLOC(_type, _size) (_type) malloc((_size))
#endif

#ifndef _CHECK_ALLOC
#define _CHECK_ALLOC(_p, _code_block)    \
    if (!(_p)) {                         \
        perror("allocate memory error"); \
        _code_block                      \
    }
#endif

struct nw_tcp_server_s {
    int listen_fd;
    nw_accept_cb_t on_accept;
};
typedef struct nw_tcp_server_s nw_tcp_server_t;

struct network_s {
    ssev_loop_t *loop;
    char *read_buf;
    int read_buf_size;
    nw_recv_cb_t on_recv;
    nw_close_cb_t on_close;
    nw_writable_cb_t on_writable;
    nw_tcp_server_t *tcp_server;
    void *userdata;
};

/* ---------------------------------------- */

static int ssev_cb(ssev_loop_t *loop, unsigned int event, int fd, void *ud);

static void setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("set reuse addr error");
    }
}

/* new connection */
static int tcp_server_accept(network_t *nw) {
    nw_tcp_server_t *serv = nw->tcp_server;
    struct sockaddr_in peer;
    socklen_t addrlen = sizeof(peer);
    int new_fd;

    while ((new_fd = accept(serv->listen_fd, (struct sockaddr *)&peer, &addrlen)) > 0) {
        /* setnonblocking(new_fd); */
        if (ssev_watch(nw->loop, SSEV_EV_READ | SSEV_EV_WRITE, new_fd, ssev_cb) != 0) {
            fprintf(stderr, "watch event error. fd:%d\n", new_fd);
            close(new_fd);
            return NW_ERR;
        }
        if (serv->on_accept) {
            serv->on_accept(nw, new_fd);
        }
        _LOG("tcp_server_accept listen_fd:%d fd:%d", serv->listen_fd, new_fd);
    }
    if (new_fd == -1) {
        if (errno != EAGAIN && errno != ECONNABORTED && errno != EPROTO && errno != EINTR) perror("accept error");
        return NW_ERR;
    }
    return NW_OK;
}

static int ssev_cb(ssev_loop_t *loop, unsigned int event, int fd, void *ud) {
    _LOG("network ssev_cb fd:%d e:%u", fd, event);
    network_t *nw = (network_t *)ssev_get_userdata(loop);
    if (!nw) {
        _LOG("network is NULL.");
        return NW_ERR;
    }
    if (event == SSEV_EV_READ) {
        if (nw->tcp_server && fd == nw->tcp_server->listen_fd) {
            tcp_server_accept(nw);
            return NW_OK;
        }
        int ret;
        do {
            memset(nw->read_buf, 0, nw->read_buf_size); /* TODO: debug */
            ret = read(fd, nw->read_buf, nw->read_buf_size);
            if (ret == 0) {
                _LOG("remove fd:%d", fd);
                /* ssev_unwatch(nw->loop, SSEV_EV_ALL, fd); */
                nw->on_close(nw, fd);
                /* close(fd); */
                break;
            } else if ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                _LOG("read EAGAIN fd:%d errno:%d", fd, errno);
                break;
            } else if ((ret == -1) && !((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                /* fprintf(stderr, "read error, remove fd:%d errno:%d\n", fd, errno); */
                _LOG("read error, remove fd:%d errno:%d", fd, errno);
                /* ssev_unwatch(nw->loop, SSEV_EV_ALL, fd); */
                nw->on_close(nw, fd);
                /* close(fd); */
                break;
            } else {
                _LOG("once read fd:%d ret:%d", fd, ret);
                nw->on_recv(nw, fd, nw->read_buf, ret);
            }
        } while (ret >= nw->read_buf_size);
        return NW_OK;
    }

    if (event == SSEV_EV_WRITE) {
        if (nw->on_writable) {
            nw->on_writable(nw, fd);
        }
    }

    return NW_OK;
}

/* ---------- network ----------*/

network_t *nw_init(ssev_loop_t *loop, int read_buf_size) {
    if (!loop || ssev_get_userdata(loop)) return NULL;
    network_t *nw = (network_t *)malloc(sizeof(network_t));
    if (!nw) {
        perror("allocate memory error");
        return NULL;
    }
    memset(nw, 0, sizeof(network_t));
    nw->on_recv = NULL;
    nw->on_close = NULL;
    nw->on_writable = NULL;
    nw->userdata = NULL;
    nw->read_buf_size = DEF_READ_BUF_SIZE;
    nw->loop = loop;
    if (read_buf_size > 0) nw->read_buf_size = read_buf_size;
    nw->read_buf = _ALLOC(char *, nw->read_buf_size);
    _CHECK_ALLOC(nw->read_buf, free(nw); return NULL;)
    memset(nw->read_buf, 0, nw->read_buf_size);
    ssev_set_userdata(loop, nw);
    return nw;
}

/* ---------- tcp ----------*/

int nw_tcp_send(network_t *nw, int fd, const char *buf, int len) {
    if (!nw || fd <= 0 || !buf || len <= 0) {
        /* error */
        return -2;
    }

    int rt, bytes;
    bytes = write(fd, buf, len);
    if (bytes == 0) {
        /* tcp close */
        rt = 0;
    } else if ((bytes == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* pending */
        rt = -1;
        _LOG("nw_tcp_send again fd:%d len:%d", fd, len);
    } else if ((bytes == -1) && !((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* error */
        perror("nw_tcp_send"); /* TODO: debug */
        rt = -2;
    } else {
        /* ok */
        rt = bytes;
    }

    return rt;
}

void nw_tcp_close(network_t *nw, int fd) {
    if (!nw || fd <= 0) {
        return;
    }
    int rt = ssev_unwatch(nw->loop, SSEV_EV_ALL, fd);
    assert(rt == 0);
    close(fd);
    _LOG("nw_tcp_close fd:%d", fd);
}

/* ---------- tcp server ----------*/

int nw_tcp_init_server(network_t *nw, const char *bind_ip, unsigned short port, nw_accept_cb_t on_accept) {
    if (!nw || !bind_ip || port <= 0 || !on_accept) {
        return NW_ERR;
    }
    int listen_fd = -1;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket error");
        return NW_ERR;
    }
    /* setnonblocking(listen_fd); */
    setreuseaddr(listen_fd);
    struct sockaddr_in sock;
    memset(&sock, 0, sizeof(struct sockaddr_in));
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = inet_addr(bind_ip);
    sock.sin_port = htons(port);
    int ret = bind(listen_fd, (struct sockaddr *)&sock, sizeof(struct sockaddr));
    if (ret == -1) {
        close(listen_fd);
        perror("bind error");
        return NW_ERR;
    }
    ret = listen(listen_fd, LISTEN_BACKLOG);
    if (ret == -1) {
        close(listen_fd);
        perror("listen error");
        return NW_ERR;
    }
    nw_tcp_server_t *serv = (nw_tcp_server_t *)malloc(sizeof(nw_tcp_server_t));
    if (!serv) {
        perror("allocate memory error");
        close(listen_fd);
        return NW_ERR;
    }
    memset(serv, 0, sizeof(nw_tcp_server_t));
    serv->listen_fd = listen_fd;
    serv->on_accept = on_accept;
    nw->tcp_server = serv;
    ret = ssev_watch(nw->loop, SSEV_EV_READ, listen_fd, ssev_cb);
    if (ret != 0) {
        _LOG("tcp server watch read event error. fd:%d", listen_fd);
        free(serv);
        close(listen_fd);
        nw->tcp_server = NULL;
        return NW_ERR;
    }
    _LOG("listen_fd:%d", listen_fd);
    return listen_fd;
}

void nw_tcp_stop_server(network_t *nw, int listen_fd) {
    if (!nw || listen_fd <= 0) return;
    nw_tcp_server_t *serv = nw->tcp_server;
    assert(serv->listen_fd == listen_fd);
    _LOG("stop server listen_fd:%d", serv->listen_fd);
    if (serv->listen_fd > 0) {
        /* epoll_ctl(nw->efd, EPOLL_CTL_DEL, serv->listen_fd, NULL); */
        ssev_unwatch(nw->loop, SSEV_EV_ALL, serv->listen_fd);
        close(serv->listen_fd);
        serv->listen_fd = 0;
    }
    free(serv);
    nw->tcp_server = NULL;
    _LOG("stop tcp server ok. %d", listen_fd);
}

/* ---------- tcp client ----------*/

int nw_tcp_connect(network_t *nw, const char *ip, unsigned short port) {
    if (!nw || !ip || port <= 0) {
        return NW_ERR;
    }
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == fd) {
        perror("socket error");
        return NW_ERR;
    }
    /* setreuseaddr(fd); */
    ssev_set_nonblocking(fd);
    int rt = connect(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (0 != rt) {
        if (errno != EINPROGRESS) {
            /* error */
            perror("tcp connect error");
            close(fd);
            return NW_ERR;
        } else {
            /* pending */
            if (ssev_watch(nw->loop, SSEV_EV_READ | SSEV_EV_WRITE, fd, ssev_cb) != 0) {
                fprintf(stderr, "watch event error. fd:%d\n", fd);
                close(fd);
                return NW_ERR;
            }
            _LOG("tcp connect pending...... fd:%d", fd);
        }
    } else {
        /* connect ok */
        _LOG("tcp connect ok. fd: %d", fd);
        if (ssev_watch(nw->loop, SSEV_EV_READ | SSEV_EV_WRITE, fd, ssev_cb) != 0) {
            fprintf(stderr, "watch event error. fd:%d\n", fd);
            close(fd);
            return NW_ERR;
        }
        nw->on_writable(nw, fd);
    }
    return fd;
}

void nw_free(network_t *nw) {
    if (!nw) return;
    if (nw->tcp_server) nw_tcp_stop_server(nw, nw->tcp_server->listen_fd);
    if (nw->read_buf) {
        free(nw->read_buf);
        nw->read_buf = NULL;
    }
    free(nw);
    _LOG("free network ok.");
}

void *nw_get_userdata(network_t *nw) {
    if (!nw) return NULL;
    return nw->userdata;
}

int nw_set_userdata(network_t *nw, void *userdata) {
    if (!nw) return NW_ERR;
    nw->userdata = userdata;
    return NW_OK;
}

int nw_set_recv_cb(network_t *nw, nw_recv_cb_t on_recv) {
    if (!nw) return NW_ERR;
    nw->on_recv = on_recv;
    return NW_OK;
}

int nw_set_close_cb(network_t *nw, nw_close_cb_t on_close) {
    if (!nw) return NW_ERR;
    nw->on_close = on_close;
    return NW_OK;
}

int nw_set_writable_cb(network_t *nw, nw_writable_cb_t on_writable) {
    if (!nw) return NW_ERR;
    nw->on_writable = on_writable;
    return NW_OK;
}
