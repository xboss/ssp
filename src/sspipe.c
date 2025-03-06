#include "sspipe.h"

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "ssbuff.h"
#include "sslog.h"

#define PACKET_HEAD_LEN 4
#define MAX_PAYLOAD_LEN (1024 * 2)
#define RECV_BUF_SIZE (MAX_PAYLOAD_LEN + PACKET_HEAD_LEN) * 5
// #define RECV_TIMEOUT 1000 * 60
// #define SEND_TIMEOUT 1000 * 60
#define POLL_TIMEOUT 1000 * 10

// static uint64_t now = 0;
// static uint64_t timecost = 0;

typedef enum { RS_RET_ERR = -1, RS_RET_OK, RS_RET_CLOSE, RS_RET_MORE } rs_ret;

inline static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

static inline int send_totally(int fd, const char* buf, int len) {
    int sent = 0, s = len;
    while (sent < len) {
        s = sstcp_send(fd, buf + sent, s - sent);
        if (s < 0) {
            return RS_RET_ERR;
        }
        sent += s;
    }
    assert(sent == len);
    return RS_RET_OK;
}

static rs_ret unpack_send(sspipe_t* pipe, ssbuff_t* ssb, int fd, char* cipher_buf, unsigned char* key,
                          unsigned char* iv) {
    assert(ssb);
    assert(pipe);
    assert(fd >= 0);
    assert(cipher_buf);

    uint32_t payload_len = 0;
    int remaining = 0;
    size_t cipher_len = 0;
    while (ssb->len > 0) {
        if (ssb->len < PACKET_HEAD_LEN) return RS_RET_MORE;
        payload_len = ntohl(*(uint32_t*)ssb->buf);
        if (payload_len > MAX_PAYLOAD_LEN || payload_len <= 0) { /* TODO: */
            _LOG_E("payload_len:%d error. max_payload:%d", payload_len, MAX_PAYLOAD_LEN);
            return RS_RET_ERR;
        }
        if (ssb->len < payload_len + PACKET_HEAD_LEN) return RS_RET_MORE;

        // decrypt
        if (key && strlen((const char*)key) > 0 && iv && strlen((const char*)iv) > 0) {
            if (crypto_decrypt(key, iv, (const unsigned char*)ssb->buf + PACKET_HEAD_LEN, payload_len,
                               (unsigned char*)cipher_buf, &cipher_len) != 0) {
                _LOG_E("unpack_send crypto_decrypt failed");
                return RS_RET_ERR;
            }
            _LOG("unpack_send crypto_decrypt ok.");
            if (send_totally(fd, cipher_buf, cipher_len) != RS_RET_OK) {
                _LOG_E("unpack_send to target failed");
                return RS_RET_ERR;
            }
        } else {
            if (send_totally(fd, ssb->buf + PACKET_HEAD_LEN, payload_len) != RS_RET_OK) {
                _LOG_E("unpack_send to target failed");
                return RS_RET_ERR;
            }
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

static rs_ret pack_send(int fd, const char* buf, int len, char* cipher_buf, unsigned char* key, unsigned char* iv) {
    assert(fd >= 0);
    assert(buf);
    assert(len > 0);
    assert(cipher_buf);

    uint32_t payload_len = 0;
    int remaining = len;
    size_t cipher_len = 0;
    while (remaining > 0) {
        // pack and send
        payload_len = remaining > MAX_PAYLOAD_LEN ? MAX_PAYLOAD_LEN : remaining;
        uint32_t payload_len_net = htonl(payload_len);
        if (send_totally(fd, (char*)&payload_len_net, PACKET_HEAD_LEN) != RS_RET_OK) {
            _LOG_E("pack_send header to target failed");
            return RS_RET_ERR;
        }
        // encrypt
        if (key && strlen((const char*)key) > 0 && iv && strlen((const char*)iv) > 0) {
            if (crypto_encrypt(key, iv, (const unsigned char*)buf + (len - remaining), payload_len,
                               (unsigned char*)cipher_buf, &cipher_len) != 0) {
                _LOG_E("pack_send crypto_encrypt failed");
                return RS_RET_ERR;
            }
            _LOG("pack_send crypto_encrypt ok.");
            if (send_totally(fd, cipher_buf, cipher_len) != RS_RET_OK) {
                _LOG_E("pack_send to target failed");
                return RS_RET_ERR;
            }
        } else {
            if (send_totally(fd, buf + (len - remaining), payload_len) != RS_RET_OK) {
                _LOG_E("pack_send to target failed");
                return RS_RET_ERR;
            }
        }
        _LOG("pack_send to target ok. payload_len:%d", payload_len);
        remaining = remaining - payload_len;
        assert(remaining >= 0);
    }
    return RS_RET_OK;
}

static rs_ret recv_and_send(int recv_fd, int send_fd, sspipe_t* pipe, sstcp_server_t* server, ssbuff_t* ssb,
                            int is_pack) {
    char buffer[RECV_BUF_SIZE] = {0};
    char cipher_buf[MAX_PAYLOAD_LEN + AES_BLOCK_SIZE] = {0};
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
        rt = pack_send(send_fd, buffer, rlen, cipher_buf, pipe->conf->key, pipe->conf->iv);
        if (rt == RS_RET_ERR) {
            _LOG_E("pack_send error.");
            return RS_RET_ERR;
        } else if (rt == RS_RET_MORE) {
            _LOG("need more data.");
            return RS_RET_MORE;
        }
        _LOG("pack_send ok.");
    } else {
        if (ssbuff_append(ssb, buffer, rlen)) {
            _LOG_E("ssbuff_append failed");
            return RS_RET_ERR;
        }

        rt = unpack_send(pipe, ssb, send_fd, cipher_buf, pipe->conf->key, pipe->conf->iv);
        if (rt == RS_RET_ERR) {
            _LOG_E("unpack_send error.");
            return RS_RET_ERR;
        } else if (rt == RS_RET_MORE) {
            _LOG("need more data.");
            return RS_RET_MORE;
        }
        _LOG("unpack_send ok.");
    }
    return RS_RET_OK;
}

static void handle_front(int front_fd, sstcp_server_t* server) {
    assert(front_fd >= 0);
    assert(server);
    sspipe_t* pipe = (sspipe_t*)server->user_data;
    assert(pipe);
    sstcp_set_nodelay(front_fd);

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
    sstcp_set_nodelay(backend->client_fd);

    // /* TODO: read timeout from config */
    // sstcp_set_recv_timeout(front_fd, RECV_TIMEOUT);
    // sstcp_set_recv_timeout(backend->client_fd, RECV_TIMEOUT);
    // sstcp_set_send_timeout(front_fd, SEND_TIMEOUT);
    // sstcp_set_send_timeout(backend->client_fd, SEND_TIMEOUT);

    ssbuff_t* front_ssb = ssbuff_init(RECV_BUF_SIZE);
    if (!front_ssb) {
        perror("create front_ssb failed");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        return;
    }
    ssbuff_t* backend_ssb = ssbuff_init(RECV_BUF_SIZE);
    if (!backend_ssb) {
        perror("create backend_ssb failed");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        ssbuff_free(front_ssb);
        return;
    }

    int is_pack = 0;
    if (pipe->conf->mode == SSPIPE_MODE_LOCAL) {
        is_pack = 1;
    }

    int infd = 0, outfd = 0;
    rs_ret rs = RS_RET_OK;
    struct pollfd fds[2] = {{.fd = front_fd, .events = POLLIN}, {.fd = backend->client_fd, .events = POLLIN}};
    while (pipe->server->running) {
        _LOG("poll wait start.");
        rt = poll(fds, 2, POLL_TIMEOUT);
        _LOG("poll wait end. rt:%d", rt);
        if (rt < 0) {
            // if (errno == EINTR || errno == EAGAIN) {
            //     _LOG("poll pending. errno:%d", errno);
            //     continue;
            // }
            perror("poll failed");
            break;
        } else if (rt == 0) {
            _LOG("poll timeout.");
            continue;
        }

        infd = (fds[0].revents & POLLIN) ? front_fd : backend->client_fd;
        outfd = infd == backend->client_fd ? front_fd : backend->client_fd;
        if (infd == front_fd) {
            rs = recv_and_send(infd, outfd, pipe, server, backend_ssb, is_pack);
        } else {
            rs = recv_and_send(infd, outfd, pipe, server, backend_ssb, !is_pack);
        }
        if (rs == RS_RET_CLOSE) {
            _LOG("recv_and_send close.");
            break;
        } else if (rs == RS_RET_MORE) {
            _LOG("need more data.");
            continue;
        } else if (rs == RS_RET_ERR) {
            _LOG_W("recv_and_send error.");
            break;
        }
    }

    ssbuff_free(front_ssb);
    ssbuff_free(backend_ssb);
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

void sspipe_stop(sspipe_t* pipe) {
    if (!pipe || !pipe->server) return;
    sstcp_stop_server(pipe->server);
    _LOG("sspipe stop ok.");
}

void sspipe_free(sspipe_t* pipe) {
    if (!pipe) return;
    if (pipe->server) {
        sstcp_free_server(pipe->server);
        pipe->server = NULL;
    }
    free(pipe);
    _LOG("sspipe free ok.");
}
