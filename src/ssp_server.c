#include "ssp_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#define BACKLOG 128

typedef struct {
    int fd;
    int is_activity;
    int is_authed;
    sspipe_t* pipe;
    ev_io* read_watcher;
    ev_io* write_watcher;
    ssp_server_t* ssp_server;
    uint64_t ctime;
} ssp_conn_t;

inline static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

inline static int set_nonblocking(int fd) {
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

inline static int setreuseaddr(int fd) {
    int reuse = 1;
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        perror("set reuse addr error");
        return _ERR;
    }
    return _OK;
}

inline static int set_nodelay(int fd) {
    int opt = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&opt, sizeof(opt)) < 0) {
        perror("Failed to set TCP_NODELAY");
        return _ERR;
    }
    return _OK;
}

static ssp_conn_t* new_conn(ssp_server_t* ssp_server, int fd, int is_activity) {
    ssp_conn_t* conn = (ssp_conn_t*)calloc(1, sizeof(ssp_conn_t));
    if (!conn) {
        _LOG_E("alloc error.");
        return NULL;
    }
    conn->fd = fd;
    conn->is_activity = is_activity;
    conn->is_authed = 0;
    conn->read_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!conn->read_watcher) {
        _LOG_E("alloc error.");
        free(conn);
        return NULL;
    }
    conn->write_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!conn->write_watcher) {
        _LOG_E("alloc error.");
        free(conn->read_watcher);
        free(conn);
        return NULL;
    }
    conn->ssp_server = ssp_server;
    conn->ctime = mstime();
    return conn;
}

static void free_conn(ssp_conn_t* conn) {
    if (!conn) return;
    _LOG("free conn. fd: %d", conn->fd);
    conn->is_activity = 0;
    if (conn->read_watcher) {
        ev_io_stop(conn->ssp_server->loop, conn->read_watcher);
        free(conn->read_watcher);
        conn->read_watcher = NULL;
    }
    if (conn->write_watcher) {
        ev_io_stop(conn->ssp_server->loop, conn->write_watcher);
        free(conn->write_watcher);
        conn->write_watcher = NULL;
    }
    free(conn);
}

static void close_conn(ssp_server_t* ssp_server, int fd) {
    if (fd < 0 || !ssp_server) return;
    sspipe_t *pipe = sspipe_get(ssp_server->sspipe_ctx, fd);
    if (!pipe) {
        _LOG("close_conn failed. fd: %d", fd);
        return;
    }
    sspipe_t *outpipe = pipe->outer;
    ssp_conn_t* conn = (ssp_conn_t*)pipe->user;
    assert(conn);
    free_conn(conn);
    sspipe_del(pipe);
    if (!outpipe) {
        _LOG("close_conn failed. fd:%d outer fd: %d", fd, outpipe->id);
        return;
    }
    ssp_conn_t* outconn = (ssp_conn_t*)outpipe->user;
    assert(outconn);
    free_conn(outconn);
    sspipe_del(outpipe);
    _LOG("close_conn fd: %d", fd);
}

static int send_all(int fd, const char* buf, int len) {
    int sent = 0, s = len;
    while (sent < len) {
        s = write(fd, buf + sent, s - sent);
        if (s < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                _LOG("send EAGAIN");
                break;
            } else {
                _LOG_E("server send failed fd: %d error: %d", fd, errno);
                sent = _ERR;
                break;
            }
        }
        if (s == 0) {
            _LOG("server send fd: %d len: %d sent: %d s: %d error: %d", fd, len, sent, s, errno);
            break;
        }
        sent += s;
    }
    return sent;
}

// return 1 is pending
int do_auth(ssp_conn_t* conn) {
    _LOG("do_auth. fd: %d", conn->fd);
    ssp_server_t* ssp_server = conn->ssp_server;
    char buf[SSP_PACKET_HEAD_LEN + SSP_TICKET_SIZE] = {0};
    int len = read(conn->fd, buf, sizeof(buf));
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // _LOG("read EAGAIN");
            return 1;
        } else {
            _LOG_E("auth read failed fd: %d error: %d", conn->fd, errno);
            return _ERR;
        }
    }
    if (len == 0) {
        // close
        _LOG("auth read EOF. fd:%d", conn->fd);
        return _ERR;
    }
    if (len != SSP_PACKET_HEAD_LEN + SSP_TICKET_SIZE) {
        _LOG_E("auth read len: %d error: %d", len, errno);
        return _ERR;
    }
    size_t payload_len = ntohl(*(uint32_t*)buf);
    if (payload_len != SSP_TICKET_SIZE) {
        _LOG_W("auth failed. payload_len: %u", payload_len);
        return _ERR;
    }
    char payload[SSP_PACKET_HEAD_LEN + SSP_TICKET_SIZE] = {0};
    payload_len = 0;
    if (strlen((const char*)ssp_server->conf->key) > 0 && strlen((const char*)ssp_server->conf->iv) > 0) {
        if (crypto_decrypt(ssp_server->conf->key, ssp_server->conf->iv, (const unsigned char*)buf + SSP_PACKET_HEAD_LEN, SSP_TICKET_SIZE, (unsigned char*)payload, (size_t*)&payload_len)) {
            _LOG_E("crypto decrypt failed when do_auth");
            return _ERR;
        }
        assert(payload_len == SSP_TICKET_SIZE);
        if (memcmp(payload, ssp_server->conf->ticket, SSP_TICKET_SIZE) != 0) {
            _LOG_W("auth failed");
            return _ERR;
        }
    } else {
        if (memcmp(buf, ssp_server->conf->ticket, SSP_TICKET_SIZE) != 0) {
            _LOG_W("auth failed");
            return _ERR;
        }
    }
    conn->is_authed = 1;
    _LOG("auth ok. fd: %d", conn->fd);
    return _OK;
}

// format: [len(4B)][ticket(32B)]
static int send_auth_req(ssp_conn_t* conn) {
    ssp_server_t* ssp_server = conn->ssp_server;
    char buf[SSP_TICKET_SIZE] = {0};
    int payload_len = strnlen(ssp_server->conf->ticket, SSP_TICKET_SIZE);
    memcpy(buf, ssp_server->conf->ticket, payload_len);
    if (sspipe_feed(conn->pipe, buf, payload_len) != _OK) {
        _LOG_E("send_auth_req sspipe_feed failed");
        return _ERR;
    }
    /* TODO: need ack? */
    // conn->is_authed = 1;
    _LOG("send_auth_req ok.");
    return _OK;
}

////////////////////////////////
// callbacks
////////////////////////////////

void free_conn_cb(void* user) {
    if (!user) return;
    ssp_conn_t* conn = (ssp_conn_t*)user;
    free_conn(conn);
    _LOG("sspipe_free_user_cb ok.");
}

static void write_cb(EV_P_ ev_io* w, int revents) {
    assert(revents & EV_WRITE);
    ssp_server_t* ssp_server = (ssp_server_t*)w->data;
    assert(ssp_server);
    int fd = w->fd;
    sspipe_t* pipe = sspipe_get(ssp_server->sspipe_ctx, fd);
    if (!pipe) {
        _LOG_E("write_cb pipe is null");
        return;
    }
    ssp_conn_t* conn = (ssp_conn_t*)pipe->user;
    assert(conn);
    if (!conn->is_activity) {
        conn->is_activity = 1;
        _LOG("write_cb activity fd: %d", fd);
    }
    // ssbuff_t* out = sspipe_take(ssp_server->sspipe_ctx, fd);
    if (!pipe->send_buf) {
        _LOG("write_cb no data");
        close_conn(ssp_server, fd);
        return;
    }
    if (pipe->send_buf->len == 0) {
        _LOG("write_cb no data");
        ev_io_stop(ssp_server->loop, w);
        return;
    }
    int sent = send_all(fd, pipe->send_buf->buf, pipe->send_buf->len);
    if (sent == _ERR) {
        _LOG_E("write_cb send_all fd: %d sent: %d", fd, sent);
        close_conn(ssp_server, fd);
        return;
    }
    if (sent < pipe->send_buf->len) {
        // pending
        _LOG("write_cb pending fd: %d sent: %d", fd, sent);
        memmove(pipe->send_buf->buf, pipe->send_buf->buf + sent, pipe->send_buf->len - sent);
        pipe->send_buf->len -= sent;
        return;
    }
    assert(sent == pipe->send_buf->len);
    pipe->send_buf->len = 0;
    ev_io_stop(ssp_server->loop, w);
    _LOG("write_cb send ok. fd: %d sent: %d", fd, sent);
}

static int sspipe_output_cb(sspipe_t* pipe) {
    assert(pipe);
    _LOG("sspipe_output_cb id: %d", pipe->id);
    ssp_conn_t* conn = (ssp_conn_t*)pipe->user;
    assert(conn);
    ssp_server_t* ssp_server = conn->ssp_server;
    assert(ssp_server);
    if (!conn->is_activity && conn->ctime + SSP_CONNECT_TIMEOUT < mstime()) { /* TODO: config timeout */
        _LOG_E("connect timeout");
        return _ERR;
    }
    ev_io* w_watcher = conn->write_watcher;
    assert(w_watcher);
    ev_io_start(ssp_server->loop, w_watcher);
    return _OK;
}

static void read_cb(EV_P_ ev_io* w, int revents) {
    assert(revents & EV_READ);
    ssp_server_t* ssp_server = (ssp_server_t*)w->data;
    assert(ssp_server);
    int fd = w->fd;
    sspipe_t* pipe = sspipe_get(ssp_server->sspipe_ctx, fd);
    if (!pipe) {
        _LOG_E("read_cb pipe is null");
        return;
    }
    ssp_conn_t* conn = (ssp_conn_t*)pipe->user;
    assert(conn);

    if (!conn->is_authed && ssp_server->conf->mode == SSP_MODE_REMOTE && !pipe->need_pack) {
        int a = do_auth(conn);
        if (a == _ERR) {
            _LOG("auth failed. close fd: %d", fd);
            close_conn(ssp_server, fd);
            return;
        }
        if (a == 1) {
            return;
        }
    }
    char buf[SSP_RECV_BUF_SIZE];
    int len = read(fd, buf, sizeof(buf));
    int ret = 0;
    do {
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // _LOG("read EAGAIN");
                break;
            } else {
                _LOG_E("server read failed fd: %d error: %d", fd, errno);
                ret = _ERR;
                break;
            }
        }
        if (len == 0) {
            // close
            _LOG("server read EOF. fd:%d", fd);
            ret = _ERR;
            break;
        }
        if (sspipe_feed(pipe, buf, len) != _OK) {
            _LOG_E("sspipe_feed failed");
            ret = _ERR;
            break;
        }
    } while (0);
    if (ret == _ERR) {
        _LOG("read_cb close fd: %d", fd);
        close_conn(ssp_server, fd);
    }
}

static void accept_cb(EV_P_ ev_io* w, int revents) {
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
        return;
    }
    set_nonblocking(back_fd);
    set_nodelay(back_fd);
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(ssp_server->conf->target_port);
    if (inet_pton(AF_INET, ssp_server->conf->target_ip, &target_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        return;
    }
    if (connect(back_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
        // _LOG_E("back connect failed error: %d", errno);
        if (errno != EINPROGRESS) {
            perror("Connection failed");
            return;
        }
    }
    _LOG("Connected to server at %s:%d", ssp_server->conf->target_ip, ssp_server->conf->target_port);
    _LOG("front_fd: %d backend_fd: %d", front_fd, back_fd);
    ssp_conn_t* front_conn = new_conn(ssp_server, front_fd, 1);
    if (!front_conn) {
        close(front_fd);
        close(back_fd);
        return;
    }
    ssp_conn_t* back_conn = new_conn(ssp_server, back_fd, 0);
    if (!back_conn) {
        close(front_fd);
        close(back_fd);
        free_conn(front_conn);
        return;
    }
    int need_pack = 0;
    if (ssp_server->conf->mode == SSP_MODE_LOCAL) {
        need_pack = 1;
    }
    sspipe_t* fpipe = sspipe_add(ssp_server->sspipe_ctx, front_fd, need_pack, sspipe_output_cb, front_conn, free_conn_cb);
    if (!fpipe) {
        _LOG_E("sspipe_add front failed");
        close(front_fd);
        close(back_fd);
        free_conn(front_conn);
        free_conn(back_conn);
        return;
    }
    sspipe_t* bpipe = sspipe_add(ssp_server->sspipe_ctx, back_fd, !need_pack, sspipe_output_cb, back_conn, free_conn_cb);
    if (!bpipe) {
        _LOG_E("sspipe_new back failed");
        close(front_fd);
        close(back_fd);
        free_conn(front_conn);
        free_conn(back_conn);
        sspipe_del(fpipe);
        return;
    }
    fpipe->user = front_conn;
    bpipe->user = back_conn;
    fpipe->outer = bpipe;
    bpipe->outer = fpipe;
    front_conn->pipe = fpipe;
    back_conn->pipe = bpipe;

    ev_io_init(back_conn->read_watcher, read_cb, back_fd, EV_READ);
    back_conn->read_watcher->data = ssp_server;

    ev_io_init(back_conn->write_watcher, write_cb, back_fd, EV_WRITE);
    back_conn->write_watcher->data = ssp_server;

    ev_io_init(front_conn->read_watcher, read_cb, front_fd, EV_READ);
    front_conn->read_watcher->data = ssp_server;

    ev_io_init(front_conn->write_watcher, write_cb, front_fd, EV_WRITE);
    front_conn->write_watcher->data = ssp_server;

    // send auth
    if (ssp_server->conf->mode == SSP_MODE_LOCAL) {
        if (send_auth_req(front_conn) != _OK) {
            _LOG_E("send_auth_req failed. close");
            close(front_fd);
            close(back_fd);
            free_conn(front_conn);
            free_conn(front_conn);
            sspipe_del(fpipe);
            sspipe_del(bpipe);
        }
    }

    ev_io_start(loop, back_conn->read_watcher);
    ev_io_start(loop, back_conn->write_watcher);
    ev_io_start(loop, front_conn->read_watcher);
}

////////////////////////////////
// API
////////////////////////////////

ssp_server_t* ssp_server_init(struct ev_loop* loop, ssconfig_t* conf) {
    ssp_server_t* ssp_server = (ssp_server_t*)calloc(1, sizeof(ssp_server_t));
    if (ssp_server == NULL) {
        _LOG_E("sspipe_init: calloc failed");
        return NULL;
    }
    ssp_server->accept_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (ssp_server->accept_watcher == NULL) {
        _LOG_E("sspipe_init: calloc failed");
        ssp_server_free(ssp_server);
        return NULL;
    }
    ssp_server->conf = conf;
    ssp_server->loop = loop;
    ssp_server->sspipe_ctx = sspipe_init(loop, (const char*)conf->key, AES_128_KEY_SIZE + 1, (const char*)conf->iv, AES_BLOCK_SIZE + 1, SSP_RECV_BUF_SIZE);
    if (ssp_server->sspipe_ctx == NULL) {
        _LOG_E("sspipe_init: sspipe_init failed");
        ssp_server_free(ssp_server);
        return NULL;
    }
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

    ev_io_init(ssp_server->accept_watcher, accept_cb, ssp_server->listen_fd, EV_READ);
    ssp_server->accept_watcher->data = ssp_server;
    ev_io_start(ssp_server->loop, ssp_server->accept_watcher);
    _LOG("server started. listen fd: %d", ssp_server->listen_fd);
    return _OK;
}

void ssp_server_stop(ssp_server_t* ssp_server) {
    if (!ssp_server) return;

    if (ssp_server->accept_watcher) {
        ev_io_stop(ssp_server->loop, ssp_server->accept_watcher);
    }
    if (ssp_server->listen_fd != -1) {
        close(ssp_server->listen_fd);
        ssp_server->listen_fd = -1;
    }
}

void ssp_server_free(ssp_server_t* ssp_server) {
    if (!ssp_server) return;

    if (ssp_server->accept_watcher) {
        free(ssp_server->accept_watcher);
        ssp_server->accept_watcher = NULL;
    }
    if (ssp_server->sspipe_ctx) {
        sspipe_free(ssp_server->sspipe_ctx);
        ssp_server->sspipe_ctx = NULL;
    }
    free(ssp_server);
}

void ssp_monitor(ssp_server_t* ssp_server) {
    _LOG("*********************************");
    _LOG("*            monitor            *")
    _LOG("*********************************");
    sspipe_print_info(ssp_server->sspipe_ctx);
    _LOG("---------------------------------");
}
