
#include "ssnet.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "sslog.h"

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

#define DEF_READ_BUF_SIZE (1500)

struct ssnet_tcp_server_s {
    int listen_fd;
};
typedef struct ssnet_tcp_server_s ssnet_tcp_server_t;

struct ssnet_udp_s {
    int fd;
    struct sockaddr_in addr;
};
typedef struct ssnet_udp_s ssnet_udp_t;

struct ssnet_s {
    ssev_loop_t *loop;
    char *read_buf;
    int read_buf_size;
    ssnet_recv_cb_t on_recv;
    ssnet_close_cb_t on_close;
    ssnet_writable_cb_t on_writable;
    ssnet_accept_cb_t on_accept;
    ssnet_tcp_server_t *tcp_server;
    ssnet_udp_t *udp;
    void *userdata;
};

/* ---------------------------------------- */

static void setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("set reuse addr error");
    }
}

/* ---------- ssnet ----------*/

ssnet_t *ssnet_init(ssev_loop_t *loop, int read_buf_size) {
    if (!loop || ssev_get_userdata(loop)) return NULL;
    ssnet_t *_ALLOC(net, ssnet_t *, sizeof(ssnet_t));
    memset(net, 0, sizeof(ssnet_t));
    net->read_buf_size = DEF_READ_BUF_SIZE;
    net->loop = loop;
    if (read_buf_size > 0) net->read_buf_size = read_buf_size;
    _ALLOC(net->read_buf, char *, net->read_buf_size);
    memset(net->read_buf, 0, net->read_buf_size);
    ssev_set_userdata(loop, net);
    return net;
}

void ssnet_free(ssnet_t *net) {
    if (!net) return;
    if (net->tcp_server) ssnet_tcp_stop_server(net, net->tcp_server->listen_fd);
    if (net->read_buf) {
        free(net->read_buf);
        net->read_buf = NULL;
    }
    if (net->udp) ssnet_udp_free(net, net->udp->fd);
    free(net);
    _LOG("free  ssnet ok.");
}

void *ssnet_get_userdata(ssnet_t *net) {
    if (!net) return NULL;
    return net->userdata;
}

int ssnet_set_userdata(ssnet_t *net, void *userdata) {
    if (!net) return _ERR;
    net->userdata = userdata;
    return _OK;
}

int ssnet_set_recv_cb(ssnet_t *net, ssnet_recv_cb_t on_recv) {
    if (!net) return _ERR;
    net->on_recv = on_recv;
    return _OK;
}

int ssnet_set_close_cb(ssnet_t *net, ssnet_close_cb_t on_close) {
    if (!net) return _ERR;
    net->on_close = on_close;
    return _OK;
}

int ssnet_set_writable_cb(ssnet_t *net, ssnet_writable_cb_t on_writable) {
    if (!net) return _ERR;
    net->on_writable = on_writable;
    return _OK;
}

/* -------- TCP -------- */

#define LISTEN_BACKLOG (128)

static int tcp_ssev_cb(ssev_loop_t *loop, unsigned int event, int fd, void *ud);

static int tcp_server_accept(ssnet_t *net) {
    ssnet_tcp_server_t *serv = net->tcp_server;
    struct sockaddr_in peer;
    socklen_t addrlen = sizeof(peer);
    int new_fd;
    while ((new_fd = accept(serv->listen_fd, (struct sockaddr *)&peer, &addrlen)) > 0) {
        /* setnonblocking(new_fd); */
        if (ssev_watch(net->loop, SSEV_EV_READ | SSEV_EV_WRITE, new_fd, tcp_ssev_cb) != 0) {
            _LOG_E("watch event error. fd:%d", new_fd);
            close(new_fd);
            return _ERR;
        }
        if (net->on_accept) {
            net->on_accept(net, new_fd);
        }
        _LOG("tcp_server_accept listen_fd:%d fd:%d", serv->listen_fd, new_fd);
    }
    if (new_fd == -1) {
        if (errno != EAGAIN && errno != ECONNABORTED && errno != EPROTO && errno != EINTR) perror("accept error");
        return _ERR;
    }
    return _OK;
}

static int tcp_ssev_cb(ssev_loop_t *loop, unsigned int event, int fd, void *ud) {
    _LOG("ssnet ssev_cb fd:%d e:%u", fd, event);
    ssnet_t *net = (ssnet_t *)ssev_get_userdata(loop);
    if (!net) {
        _LOG("ssnet is NULL.");
        return _ERR;
    }
    if (event == SSEV_EV_READ) {
        if (net->tcp_server && fd == net->tcp_server->listen_fd) {
            tcp_server_accept(net);
            return _OK;
        }
        int ret;
        do {
            memset(net->read_buf, 0, net->read_buf_size); /* TODO: debug */
            ret = read(fd, net->read_buf, net->read_buf_size);
            if (ret == 0) {
                _LOG("remove fd:%d", fd);
                net->on_close(net, fd);
                /* close(fd); */
                break;
            } else if ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                _LOG("read EAGAIN fd:%d errno:%d", fd, errno);
                break;
            } else if ((ret == -1) && !((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
                /* _LOG_E( "read error, remove fd:%d errno:%d", fd, errno); */
                _LOG("read error, remove fd:%d errno:%d", fd, errno);
                net->on_close(net, fd);
                /* close(fd); */
                break;
            } else {
                _LOG("once read fd:%d ret:%d", fd, ret);
                net->on_recv(net, fd, net->read_buf, ret, NULL);
            }
        } while (ret >= net->read_buf_size);
        return _OK;
    }
    if (event == SSEV_EV_WRITE) {
        if (net->on_writable) {
            net->on_writable(net, fd);
        }
    }
    return _OK;
}

int ssnet_tcp_send(ssnet_t *net, int fd, const char *buf, int len) {
    if (!net || fd <= 0 || !buf || len <= 0) return -2;
    int rt, bytes;
    bytes = write(fd, buf, len);
    if (bytes == 0) {
        /* tcp close */
        rt = 0;
    } else if ((bytes == -1) && ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* pending */
        rt = -1;
        _LOG("net_tcp_send again fd:%d len:%d", fd, len);
    } else if ((bytes == -1) && !((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))) {
        /* error */
        perror("net_tcp_send"); /* TODO: debug */
        rt = -2;
    } else {
        /* ok */
        rt = bytes;
    }

    return rt;
}

void ssnet_tcp_close(ssnet_t *net, int fd) {
    if (!net || fd <= 0) return;
    int rt = ssev_unwatch(net->loop, SSEV_EV_ALL, fd);
    assert(rt == 0);
    close(fd);
    _LOG("net_tcp_close fd:%d", fd);
}

/* ---------- tcp server ----------*/

int ssnet_tcp_init_server(ssnet_t *net, const char *bind_ip, unsigned short port, ssnet_accept_cb_t on_accept) {
    if (!net || !bind_ip || port <= 0 || !on_accept) return _ERR;
    int listen_fd = -1;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket error");
        return _ERR;
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
        return _ERR;
    }
    ret = listen(listen_fd, LISTEN_BACKLOG);
    if (ret == -1) {
        close(listen_fd);
        perror("listen error");
        return _ERR;
    }
    ssnet_tcp_server_t *_ALLOC(serv, ssnet_tcp_server_t *, sizeof(ssnet_tcp_server_t));
    memset(serv, 0, sizeof(ssnet_tcp_server_t));
    serv->listen_fd = listen_fd;
    net->on_accept = on_accept;
    net->tcp_server = serv;
    ret = ssev_watch(net->loop, SSEV_EV_READ, listen_fd, tcp_ssev_cb);
    if (ret != 0) {
        _LOG("tcp server watch read event error. fd:%d", listen_fd);
        free(serv);
        close(listen_fd);
        net->tcp_server = NULL;
        return _ERR;
    }
    _LOG("listen_fd:%d", listen_fd);
    return listen_fd;
}

void ssnet_tcp_stop_server(ssnet_t *net, int listen_fd) {
    if (!net || listen_fd <= 0) return;
    ssnet_tcp_server_t *serv = net->tcp_server;
    assert(serv->listen_fd == listen_fd);
    _LOG("stop server listen_fd:%d", serv->listen_fd);
    if (serv->listen_fd > 0) {
        /* epoll_ctl(net->efd, EPOLL_CTL_DEL, serv->listen_fd, NULL); */
        ssev_unwatch(net->loop, SSEV_EV_ALL, serv->listen_fd);
        close(serv->listen_fd);
        serv->listen_fd = 0;
    }
    free(serv);
    net->tcp_server = NULL;
    _LOG("stop tcp server ok. %d", listen_fd);
}

/* ---------- tcp client ----------*/

int ssnet_tcp_connect(ssnet_t *net, const char *ip, unsigned short port) {
    if (!net || !ip || port <= 0) {
        return _ERR;
    }
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &servaddr.sin_addr);
    servaddr.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == fd) {
        perror("socket error");
        return _ERR;
    }
    /* setreuseaddr(fd); */
    ssev_set_nonblocking(fd);
    int rt = connect(fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (0 != rt) {
        if (errno != EINPROGRESS) {
            /* error */
            perror("tcp connect error");
            close(fd);
            return _ERR;
        } else {
            /* pending */
            if (ssev_watch(net->loop, SSEV_EV_READ | SSEV_EV_WRITE, fd, tcp_ssev_cb) != 0) {
                _LOG_E("watch event error. fd:%d", fd);
                close(fd);
                return _ERR;
            }
            _LOG("tcp connect pending...... fd:%d", fd);
        }
    } else {
        /* connect ok */
        _LOG("tcp connect ok. fd: %d", fd);
        if (ssev_watch(net->loop, SSEV_EV_READ | SSEV_EV_WRITE, fd, tcp_ssev_cb) != 0) {
            _LOG_E("watch event error. fd:%d", fd);
            close(fd);
            return _ERR;
        }
        net->on_writable(net, fd);
    }
    return fd;
}

/* -------- UDP -------- */

/* static int is_target_addr_empty(ssnet_t *net) {
    if (!net) return 1;
    struct sockaddr_in tmp;
    memset(&tmp, 0, sizeof(struct sockaddr_in));
    if (memcmp(&tmp, &net->udp->target_addr, sizeof(struct sockaddr_in)) == 0) return 1;
    return 0;
} */

static int udp_ssev_cb(ssev_loop_t *loop, unsigned int event, int fd, void *ud) {
    _LOG("ssnet ssev_cb fd:%d e:%u", fd, event);
    ssnet_t *net = (ssnet_t *)ssev_get_userdata(loop);
    assert(net);
    assert(net->udp);
    assert(net->udp->fd == fd);
    if (event == SSEV_EV_READ) {
        /* struct sockaddr_in addr; */
        int addr_len = sizeof(net->udp->addr);
        int rlen = recvfrom(fd, net->read_buf, net->read_buf_size, 0, (struct sockaddr *)&net->udp->addr,
                            (socklen_t *)&addr_len);
        if (rlen <= 0) {
            _LOG_E("udp recv error %s", strerror(errno));
            return _ERR;
        }
        if (net->on_recv) net->on_recv(net, fd, net->read_buf, rlen, (struct sockaddr *)&net->udp->addr);
    }
    return _OK;
}

int ssnet_udp_init(ssnet_t *net, const char *ip, unsigned short port, int is_bind) {
    if (!net || !ip || port <= 0) return _ERR;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == fd) return _ERR;
    struct sockaddr_in addr;
    bzero(&addr, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    if (is_bind) {
        if (-1 == bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
            close(fd);
            return _ERR;
        }
    }
    if (ssev_watch(net->loop, SSEV_EV_READ, fd, udp_ssev_cb) != 0) {
        _LOG_E("watch event error. fd:%d", fd);
        close(fd);
        return _ERR;
    }
    ssnet_udp_t *_ALLOC(udp, ssnet_udp_t *, sizeof(ssnet_udp_t));
    memset(udp, 0, sizeof(ssnet_udp_t));
    udp->fd = fd;
    net->udp = udp;
    return fd;
}

void ssnet_udp_free(ssnet_t *net, int fd) {
    if (!net || fd <= 0 || !net->udp) return;
    assert(net->udp->fd == fd);
    int rt = ssev_unwatch(net->loop, SSEV_EV_ALL, fd);
    assert(rt == 0);
    close(fd);
    free(net->udp);
    net->udp = NULL;
    _LOG("ssnet_udp_free and close fd:%d", fd);
}

int ssnet_udp_send(ssnet_t *net, int fd, const char *buf, int len, const struct sockaddr *addr) {
    if (!net || fd <= 0 || !buf || len <= 0) return _ERR;
    int wlen = sendto(net->udp->fd, buf, len, 0, addr, sizeof(*addr));
    if (wlen <= 0) {
        _LOG_E("udp send error %s", strerror(errno));
        return _ERR;
    }
    return wlen;
}