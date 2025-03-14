#include "ssp_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>

#define BACKLOG 128

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("Error getting file flags");
        return _ERR;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("Error setting file to non-blocking mode");
        return _ERR;
    }
    return _OK;
}

static int setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("set reuse addr error");
        return _ERR;
    }
    return _OK;
}

static int set_nodelay(int fd) {
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt)) < 0) {
        perror("Failed to set TCP_NODELAY");
        return _ERR;
    }
    return _OK;
}

////////////////////////////////
// callbacks
////////////////////////////////

int sspipe_output_cb(const char* buf, int len, int id, void* user){
    /* TODO: start write watcher */
    // int sent = 0, s = len;
    // while (sent < len) {
    //     s = send(id, buf + sent, s - sent, 0);
    //     if (s < 0) {
    //         if (errno == EAGAIN || errno == EWOULDBLOCK) {
    //             _LOG("send EAGAIN");
    //             return;
    //         } else {
    //             _LOG_E("server send failed");
    //             return _ERR;
    //         }
    //     }
    //     if (s < 0) {
    //         return _ERR;
    //     }
    //     sent += s;
    // }
    // assert(sent == len);
    return _OK;
}

static void accept_cb(EV_P_ ev_io *w, int revents) {
    assert(revents & EV_READ);
    ssp_server_t* ssp_server = (ssp_server_t*)w->data;
    assert(ssp_server);
    
    struct sockaddr_in front_addr;
    socklen_t len = sizeof(front_addr);
    int front_fd = accept(w->fd, (struct sockaddr*)&front_addr, &len);
    if (front_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            _LOG("accept EAGAIN");
            return;
        } else {
            perror("server accept failed");
            return;
        }
    }
    set_nonblocking(front_fd);
    set_nodelay(front_fd);

    // connect to target server
    int back_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (back_fd < 0) {
        perror("back socket creation failed");
        return _ERR;
    }
    set_nonblocking(back_fd);
    set_nodelay(back_fd);
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(ssp_server->conf->target_port);
    if (inet_pton(AF_INET, ssp_server->conf->target_ip, &target_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        return _ERR;
    }
    if (connect(back_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        perror("Connection failed");
        return _ERR;
    }
    _LOG("Connected to server at %s:%d", ssp_server->conf->target_ip, ssp_server->conf->target_port);
    _LOG("front_fd: %d backend_fd: %d", front_fd, back_fd);
    
    sspipe_type_t ssp_type = SSPIPE_TYPE_UNPACK;
    if (ssp_server->conf->mode == SSP_MODE_LOCAL) {
        ssp_type = SSPIPE_TYPE_PACK;
    }
    if (sspipe_new(ssp_server->sspipe_ctx, front_fd, ssp_type, sspipe_output_cb, ssp_server) != _OK) {
        _LOG_E("sspipe_new failed");
        close(front_fd);
        close(back_fd);
        return;
    }
    if (sspipe_new(ssp_server->sspipe_ctx, back_fd, !ssp_type, sspipe_output_cb, ssp_server) != _OK) {
        _LOG_E("sspipe_new failed");
        close(front_fd);
        close(back_fd);
        sspipe_del(ssp_server->sspipe_ctx, front_fd);
        return;
    }
    if (sspipe_bind(ssp_server->sspipe_ctx, front_fd, back_fd)!= _OK) {
        _LOG_E("sspipe_bind failed");
        close(front_fd);
        close(back_fd);
        sspipe_del(ssp_server->sspipe_ctx, front_fd);
        sspipe_del(ssp_server->sspipe_ctx, back_fd);
        return;
    }
}

////////////////////////////////
// API
////////////////////////////////

ssp_server_t* ssp_server_init(ssconfig_t* conf) {
    ssp_server_t* ssp_server = (ssp_server_t*)calloc(1, sizeof(ssp_server_t));
    if (ssp_server == NULL) {
        _LOG_E("sspipe_init: calloc failed");
        return NULL;
    }
    ssp_server->conf = conf;
    ssp_server->sspipe_ctx = sspipe_init((const char*)conf->key, AES_128_KEY_SIZE + 1, (const char*)conf->iv, AES_BLOCK_SIZE + 1, SSP_RECV_BUF_SIZE);
    if (ssp_server->sspipe_ctx == NULL) {
        _LOG_E("sspipe_init: sspipe_init failed");
        ssp_server_free(ssp_server);
        return NULL;
    }

    /* TODO: */
    return ssp_server;
}

int ssp_server_start(ssp_server_t* ssp_server) {
    if (ssp_server == NULL) {
        _LOG_E("ssp_server_start: ssp_server is NULL");
        return _ERR;
    }
    struct sockaddr_in servaddr;
    if ((ssp_server->listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket creation failed");
        return _ERR;
    }
    setreuseaddr(ssp_server->listen_fd);
    set_nonblocking(ssp_server->listen_fd);
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(ssp_server->conf->listen_port);
    if (inet_pton(AF_INET, ssp_server->conf->listen_ip, &servaddr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(ssp_server->listen_fd);
        return _ERR;
    }
    if (bind(ssp_server->listen_fd, (const struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        perror("socket bind failed");
        close(ssp_server->listen_fd);
        return _ERR;
    }
    if (listen(ssp_server->listen_fd, BACKLOG) != 0) {
        perror("socket listen failed");
        close(ssp_server->listen_fd);
        return _ERR;
    }

    ssp_server->accept_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    ev_io_init(ssp_server->accept_watcher, accept_cb, ssp_server->listen_fd, EV_READ);
    ssp_server->accept_watcher->data = ssp_server;
    ev_io_start(ssp_server->loop, ssp_server->accept_watcher);

    // skt->udp_r_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    // if (!skt->udp_r_watcher) {
    //     perror("alloc udp_r_watcher");
    //     skt_free(skt);
    //     return NULL;
    // }
    // skt->udp_r_watcher->data = skt;
    /* TODO: */
    return _OK;
}

void ssp_server_stop(ssp_server_t* ssp_server) {
    /* TODO: */
    return;
}

void ssp_server_free(ssp_server_t* ssp_server) {
    /* TODO: */
    return;
}
