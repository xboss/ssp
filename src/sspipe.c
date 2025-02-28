#include "sspipe.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "sslog.h"

#define PACKET_HEAD_LEN 4
// #define MAX_PAYLOAD_LEN (1024 * 1)
#define RECV_BUF_SIZE 1024 * 10
// #define RECV_BUF_SIZE (MAX_PAYLOAD_LEN + PACKET_HEAD_LEN) * 2
#define RECV_TIMEOUT 1000 * 60
// #define SEND_TIMEOUT 1000 * 60

/////////////////////////

typedef struct {
    char* buf;  // 动态缓冲区
    int len;    // 当前缓冲长度
    int cap;    // 缓冲区容量
} ssbuffer_t;

static ssbuffer_t* ssbuffer_create() {
    ssbuffer_t* ssb = (ssbuffer_t*)calloc(1, sizeof(ssbuffer_t));
    if (!ssb) {
        return NULL;
    }
    return ssb;
}

static void ssbuffer_free(ssbuffer_t* ssb) {
    if (ssb) {
        if (ssb->buf) {
            free(ssb->buf);
            ssb->buf = NULL;
        }
        free(ssb);
    }
}

static int ssbuffer_grow(ssbuffer_t* ssb, int len) {
    if (ssb->len + len > ssb->cap) {
        int new_cap = ssb->cap * 3 / 2;
        if (new_cap < ssb->len + len) {
            new_cap = ssb->len + len;
        }
        char* new_buf = (char*)calloc(1, new_cap);
        if (!new_buf) {
            return _ERR;
        }
        if (ssb->buf) {
            memcpy(new_buf, ssb->buf, ssb->len);
            free(ssb->buf);
        }
        ssb->buf = new_buf;
        ssb->cap = new_cap;
    }
    return _OK;
}

/////////////////////////

typedef enum { RS_RET_ERR = -1, RS_RET_OK, RS_RET_CLOSE, RS_RET_MORE } rs_ret;

/**
 * @brief
 * @param ssb
 * @param client
 * @return 0: ok, 1: need more data (continue), -1: error(break)
 */
rs_ret unpack_send(sspipe_t* pipe, ssbuffer_t* ssb, int fd) {
    assert(ssb);
    assert(pipe);
    assert(fd >= 0);
    int rt = 0;
    uint32_t payload_len = 0;
    int remaining = 0;
    while (ssb->len > 0) {
        if (ssb->len < PACKET_HEAD_LEN) return RS_RET_MORE;
        payload_len = ntohl(*(uint32_t*)ssb->buf);
        if (payload_len > 65536 || payload_len <= 0) { /* TODO: */
            _LOG_E("payload_len:%d error. max_payload:%d", payload_len, 65536);
            return RS_RET_ERR;
        }
        if (ssb->len < payload_len + PACKET_HEAD_LEN) return RS_RET_MORE;

        /* TODO: decrypt */

        rt = sstcp_send(fd, ssb->buf + PACKET_HEAD_LEN, payload_len);
        if (rt < 0) {
            perror("unpack_send to target failed");
            return RS_RET_ERR;
        }
        _LOG("unpack_send to target ok.");

        remaining = ssb->len - (payload_len + PACKET_HEAD_LEN);
        assert(remaining >= 0);
        if (remaining > 0) {
            memmove(ssb->buf, ssb->buf + payload_len + PACKET_HEAD_LEN, remaining);
        }
        ssb->len = remaining;
    }
    return RS_RET_OK;
}

/**
 * @brief
 * @return 0: ok, 1: need more data (continue), -1: error(break)
 */
int pack_send(int fd, const char* buf, int len) {
    assert(fd >= 0);
    assert(buf);
    assert(len > 0);

    int rt = 0;
    uint32_t payload_len = 0;
    int remaining = len;
    while (remaining > 0) {
        /* TODO: encrypt */

        // pack and send
        // payload_len = remaining > MAX_PAYLOAD_LEN ? MAX_PAYLOAD_LEN : remaining;
        payload_len = remaining;
        uint32_t payload_len_net = htonl(payload_len);
        rt = sstcp_send(fd, (char*)&payload_len_net, PACKET_HEAD_LEN);
        if (rt < 0) {
            _LOG_E("pack_send to target failed");
            return RS_RET_ERR;
        }
        assert(rt == PACKET_HEAD_LEN);
        rt = sstcp_send(fd, buf + (len - remaining), payload_len);
        if (rt < 0) {
            _LOG_E("pack_send to target failed");
            return RS_RET_ERR;
        }
        _LOG("pack_send to target ok. rt:%d payload_len:%d", rt, payload_len);
        // assert(rt == payload_len);

        remaining = remaining - rt;
        assert(remaining >= 0);
    }
    return RS_RET_OK;
}

/**
 * @brief
 * @return 0: ok, 1: need more data (continue), -1: error(break)
 */
static int recv_and_send(int recv_fd, int send_fd, sspipe_t* pipe, sstcp_server_t* server, ssbuffer_t* ssb,
                         int is_pack) {
    char buffer[RECV_BUF_SIZE] = {0};
    // 读取客户端数据
    int rlen = 0;
    int rt = 0;
    rlen = sstcp_receive(recv_fd, buffer, sizeof(buffer));
    if (rlen == 0) {
        _LOG("client closed.");
        return RS_RET_CLOSE;
    } else if (rlen < 0) {
        perror("recv failed");
        return RS_RET_ERR;
    }
    _LOG("Received: %d", rlen);

    if (is_pack) {
        rt = pack_send(send_fd, buffer, rlen);
        if (rt == -1) {
            _LOG_E("pack_send error.");
            // break;
            return RS_RET_ERR;
        } else if (rt == 1) {
            _LOG("need more data.");
            // continue;
            return RS_RET_MORE;
        }
        _LOG("pack_send ok.");
    } else {
        rt = ssbuffer_grow(ssb, rlen);
        if (rt != _OK) {
            _LOG_E("ssbuffer_grow failed");
            // break;
            return RS_RET_ERR;
        }
        memcpy(ssb->buf + ssb->len, buffer, rlen);
        ssb->len += rlen;
        rt = unpack_send(pipe, ssb, send_fd);
        if (rt == -1) {
            _LOG_E("unpack_send error.");
            // break;
            return RS_RET_ERR;
        } else if (rt == 1) {
            _LOG("need more data.");
            // continue;
            return RS_RET_MORE;
        }
        _LOG("unpack_send ok.");
    }
    return RS_RET_OK;
}

void handle_front(int front_fd, sstcp_server_t* server) {
    assert(front_fd >= 0);
    assert(server);
    sspipe_t* pipe = (sspipe_t*)server->user_data;
    assert(pipe);

    _LOG("handle_front accept: %d", front_fd);
    sstcp_client_t* backend = sstcp_create_client();
    if (!backend) {
        perror("create client failed");
        return;
    }

    int rt = sstcp_connect(backend, pipe->conf->target_ip, pipe->conf->target_port);
    if (rt != _OK) {
        _LOG_E("connect to target failed. %d %s:%d", backend->client_fd, pipe->conf->target_ip,
               pipe->conf->target_port);
        perror("connect to target failed");
        sstcp_free_client(backend);
        return;
    }
    _LOG("connect to target ok. %d %s:%d", backend->client_fd, pipe->conf->target_ip, pipe->conf->target_port);

    /* TODO: read timeout from config */
    // sstcp_set_recv_timeout(front_fd, RECV_TIMEOUT);
    // sstcp_set_recv_timeout(backend->client_fd, RECV_TIMEOUT);
    // sstcp_set_send_timeout(front_fd, SEND_TIMEOUT);
    // sstcp_set_send_timeout(backend->client_fd, SEND_TIMEOUT);

    ssbuffer_t* front_ssb = ssbuffer_create();
    if (!front_ssb) {
        perror("create front_ssb failed");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        return;
    }
    ssbuffer_t* backend_ssb = ssbuffer_create();
    if (!backend_ssb) {
        perror("create backend_ssb failed");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        return;
    }

    int is_pack = 0;
    if (pipe->conf->mode == SSPIPE_MODE_LOCAL) {
        is_pack = 1;
    }

    int is_stop = 0;
    rs_ret rs = RS_RET_OK;
    struct pollfd fds[2] = {{.fd = front_fd, .events = POLLIN}, {.fd = backend->client_fd, .events = POLLIN}};
    while (pipe->server->running && !is_stop) {
        rt = poll(fds, 2, RECV_TIMEOUT);
        if (rt < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                _LOG("poll pending. errno:%d", errno);
                continue;
            }
            perror("poll failed");
            break;
        } else if (rt == 0) {
            _LOG("poll timeout.");
            continue;
        }

        for (int i = 0; i < 2; ++i) {
            if (fds[i].revents & POLLIN) {
                if (fds[i].fd == front_fd) {
                    // read front data
                    rs = recv_and_send(front_fd, backend->client_fd, pipe, server, front_ssb, is_pack);
                } else {
                    // read backend data
                    rs = recv_and_send(backend->client_fd, front_fd, pipe, server, backend_ssb, !is_pack);
                }
                if (rs == RS_RET_CLOSE) {
                    _LOG_E("recv_and_send close. fd:%d", fds[i].fd);
                    is_stop = 1;
                    break;
                } else if (rs == RS_RET_MORE) {
                    _LOG("need more data. fd:%d", fds[i].fd);
                    continue;
                } else if (rs == RS_RET_ERR) {
                    _LOG_E("recv_and_send error. fd:%d", fds[i].fd);
                    is_stop = 1;
                    break;
                }
            }
        }

        // // read front data
        // rt = recv_and_send(front_fd, backend->client_fd, pipe, server, front_ssb, is_pack);
        // if (rt == _ERR) {
        //     _LOG_E("front recv_and_send error.");
        //     break;
        // } else if (rt == 1) {
        //     _LOG("front need more data.");
        //     continue;
        // }
        // _LOG("front recv_and_send ok. front_ssb->len:%d", front_ssb->len);

        // // read backend data
        // while (pipe->server->running) {
        //     rt = recv_and_send(backend->client_fd, front_fd, pipe, server, backend_ssb, !is_pack);
        //     if (rt == _ERR) {
        //         _LOG_E("backend recv_and_send error.");
        //         break;
        //     } else if (rt == 1) {
        //         _LOG("backend need more data.");
        //         continue;
        //     }
        //     _LOG("backend recv_and_send ok. backend_ssb->len:%d", backend_ssb->len);
        //     break;
        // }
    }

    /* TODO: */

    ssbuffer_free(front_ssb);
    ssbuffer_free(backend_ssb);
    sstcp_close(backend->client_fd);
    sstcp_free_client(backend);
    _LOG("handle_front exit.");
}

/* ---------- api ----------- */

sspipe_t* sspipe_init(ssconfig_t* conf) {
    if (!conf) return NULL;

    sspipe_t* pipe = (sspipe_t*)calloc(1, sizeof(sspipe_t));
    if (pipe == NULL) {
        return NULL;
    }
    sstcp_server_t* server = sstcp_create_server(conf->listen_ip, conf->listen_port, handle_front, pipe);
    if (!server) {
        _LOG_E("create tcp server error.");
        sspipe_free(pipe);
        return NULL;
    }
    pipe->server = server;
    pipe->conf = conf;

    return pipe;
}

int sspipe_start(sspipe_t* pipe) {
    if (!pipe) return _ERR;
    sstcp_server_t* server = pipe->server;
    if (!server) return _ERR;
    return sstcp_start_server(server);
}

void sspipe_free(sspipe_t* pipe) {
    if (!pipe) return;
    if (pipe->server) {
        if (pipe->server->running) sstcp_stop_server(pipe->server);
        sstcp_free_server(pipe->server);
        pipe->server = NULL;
    }
    free(pipe);
    _LOG("sspipe free ok.");
}
