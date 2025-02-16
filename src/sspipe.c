#include "sspipe.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "sslog.h"

/* ---------- protocol ----------- */
#define PACKET_HEAD_LEN 4
#define MAX_PAYLOAD_LEN (1024 * 1)

// static int pack(int payload_len, const char* payload, char** buf) {
//     if (payload_len <= 0 || !payload) {
//         return 0;
//     }
//     _ALLOC(*buf, char*, payload_len + PACKET_HEAD_LEN);
//     memset(*buf, 0, payload_len + PACKET_HEAD_LEN);
//     int n_payload_len = htonl(payload_len);
//     memcpy(*buf, &n_payload_len, PACKET_HEAD_LEN);
//     memcpy(*buf + PACKET_HEAD_LEN, payload, payload_len);
//     return payload_len + PACKET_HEAD_LEN;
// }

// static int unpack(char** p, int len, int* payload_len) {
//     _LOG("uppack len:%d", len);
//     assert(p);
//     assert(*p);
//     assert(len > 0);
//     if (len < PACKET_HEAD_LEN) {
//         return _ERR;
//     }
//     *payload_len = ntohl(*(uint32_t*)(*p));
//     if (*payload_len <= 0 || *payload_len > 65535) {
//         /* TODO: debug */
//         _LOG_E("unpack payload_len:%d error, len:%d", *payload_len, len);
//     }
//     /* assert(*payload_len > 0 && *payload_len < 65535); */

//     if (len < *payload_len + PACKET_HEAD_LEN) {
//         return _ERR;
//     }
//     *p += PACKET_HEAD_LEN;
//     _LOG("uppack len:%d payload_len:%d ok.", len, *payload_len);
//     return _OK;
// }

/* --------------------- */

// static char* encrypt_and_pack(int fd, const char* buf, int len, char* key, int* pk_len) {
//     char* cihper = (char*)buf;
//     int cipher_len = len;
//     char* pk_buf = (char*)cihper;
//     *pk_len = cipher_len;
//     if (pconn_is_secret(fd)) {
//         assert(fd > 0);
//         cihper = aes_encrypt(key, buf, len, &cipher_len);
//         _LOG("encrypt ");
//         assert(cipher_len % 16 == 0);
//         *pk_len = pack(cipher_len, cihper, &pk_buf);
//         free(cihper);
//         assert(*pk_len >= 0);
//     }
//     return pk_buf;
// }

void echo(int client_socket, sstcp_server_t* server) {
    char buffer[1024] = {0};
    // char* hello = "Hello from server";
    // 读取客户端数据
    int valread = 0;
    while (server->running) {
        memset(buffer, 0, sizeof(buffer));
        valread = sstcp_receive(client_socket, buffer, 1024);
        if (valread > 0) {
            _LOG("Received: %s", buffer);
            // 发送响应
            // sstcp_send(client_socket, hello, strlen(hello));
            sstcp_send(client_socket, buffer, valread);
            _LOG("Hello message sent to client");
        } else {
            perror("recv failed");
            break;
        }
    }
}

/* ---------- callback ----------- */

typedef struct {
    char* buf;             // 动态缓冲区
    int len;               // 当前缓冲长度
    int cap;               // 缓冲区容量
    uint32_t max_payload;  // 允许的最大负载长度（可配置）
} ssbuffer_t;

static ssbuffer_t* ssbuffer_create(uint32_t max_payload) {
    ssbuffer_t* ssb = (ssbuffer_t*)calloc(1, sizeof(ssbuffer_t));
    if (!ssb) {
        return NULL;
    }
    ssb->max_payload = max_payload;
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

/**
 * @brief 
 * @param ssb 
 * @param client 
 * @return 0: ok, 1: need more data (continue), -1: error(break)
 */
int handle_remote(ssbuffer_t* ssb, sstcp_client_t* client) {
    assert(ssb);
    assert(client);
    int rt = 0;
    uint32_t payload_len = 0;
    int remaining = 0;
    while (ssb->len > 0) {
        if (ssb->len < PACKET_HEAD_LEN) return 1;
        payload_len = ntohl(*(uint32_t*)ssb->buf);
        if (payload_len > ssb->max_payload || payload_len <= 0) {
            _LOG_E("payload_len:%d error. max_payload:%d", payload_len, ssb->max_payload);
            return -1;
        }
        if (ssb->len < payload_len + PACKET_HEAD_LEN) return 1;

        /* TODO: crypt */

        rt = sstcp_send(client->client_fd, ssb->buf, payload_len + PACKET_HEAD_LEN);
        if (rt < 0) {
            perror("send to target failed");
            return -1;
        }
        _LOG("send to target ok.");

        remaining = ssb->len - (payload_len + PACKET_HEAD_LEN);
        assert(remaining >= 0);
        if (remaining > 0) {
            memmove(ssb->buf, ssb->buf + payload_len + PACKET_HEAD_LEN, remaining);
        }
        ssb->len = remaining;
    }
    return 0;
}

void handle_local() {}

void handle_client(int client_socket, sstcp_server_t* server) {
    assert(client_socket >= 0);
    assert(server);
    sspipe_t* pipe = (sspipe_t*)server->user_data;
    assert(pipe);

    _LOG("handle_client accept: %d", client_socket);
    sstcp_client_t* client = sstcp_create_client();
    if (!client) {
        perror("create client failed");
        return;
    }

    int rt = sstcp_connect(client, pipe->conf->target_ip, pipe->conf->target_port);
    if (rt != _OK) {
        _LOG_E("connect to target failed. %d %s:%d", client->client_fd, pipe->conf->target_ip, pipe->conf->target_port);
        perror("connect to target failed");
        sstcp_free_client(client);
        return;
    }

    ssbuffer_t* ssb = ssbuffer_create(MAX_PAYLOAD_LEN);
    if (!ssb) {
        perror("create ssbuffer failed");
        sstcp_close(client->client_fd);
        sstcp_free_client(client);
        return;
    }

    char buffer[PACKET_HEAD_LEN + MAX_PAYLOAD_LEN] = {0};
    // 读取客户端数据
    int rlen = 0;
    while (server->running) {
        rlen = sstcp_receive(client_socket, buffer, sizeof(buffer));
        if (rlen <= 0) {
            perror("recv failed");
            break;
        }
        _LOG("Received: %d", rlen);
        rt = ssbuffer_grow(ssb, rlen);
        if (rt != _OK) {
            _LOG_E("ssbuffer_grow failed");
            break;
        }
        memcpy(ssb->buf + ssb->len, buffer, rlen);
        ssb->len += rlen;

   /* TODO: */
        rt = handle_remote(ssb, client);
        if (rt == -1) {
            _LOG_E("handle_remote error.");
            break;
        } else if (rt == 1) {
            _LOG("need more data.");
            continue;
        }
    }
    ssbuffer_free(ssb);
    sstcp_close(client->client_fd);
    sstcp_free_client(client);

    /* TODO: */
}

/* ---------- api ----------- */

sspipe_t* sspipe_init(ssconfig_t* conf) {
    if (!conf) return NULL;

    sspipe_t* pipe = (sspipe_t*)calloc(1, sizeof(sspipe_t));
    if (pipe == NULL) {
        return NULL;
    }
    sstcp_server_t* server = sstcp_create_server(conf->listen_ip, conf->listen_port, handle_client, pipe);
    if (!server) {
        _LOG_E("create tcp server error.");
        sspipe_free(pipe);
        return NULL;
    }
    pipe->server = server;
    pipe->conf = conf;

    return pipe;
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
