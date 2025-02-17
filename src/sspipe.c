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

/**
 * @brief
 * @param ssb
 * @param client
 * @return 0: ok, 1: need more data (continue), -1: error(break)
 */
int unpack_send(sspipe_t* pipe, ssbuffer_t* ssb, int fd) {
    assert(ssb);
    assert(pipe);
    assert(fd >= 0);
    int rt = 0;
    uint32_t payload_len = 0;
    int remaining = 0;
    while (ssb->len > 0) {
        if (ssb->len < PACKET_HEAD_LEN) return 1;
        payload_len = ntohl(*(uint32_t*)ssb->buf);
        if (payload_len > MAX_PAYLOAD_LEN || payload_len <= 0) {
            _LOG_E("payload_len:%d error. max_payload:%d", payload_len, MAX_PAYLOAD_LEN);
            return -1;
        }
        if (ssb->len < payload_len + PACKET_HEAD_LEN) return 1;

        /* TODO: decrypt */

        rt = sstcp_send(fd, ssb->buf + 4, payload_len);
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
        payload_len = remaining > MAX_PAYLOAD_LEN ? MAX_PAYLOAD_LEN : remaining;
        uint32_t payload_len_net = htonl(payload_len);
        rt = sstcp_send(fd, (char*)&payload_len_net, PACKET_HEAD_LEN);
        if (rt < 0) {
            _LOG_E("send to target failed");
            return -1;
        }
        rt = sstcp_send(fd, buf - (len - remaining), payload_len);
        if (rt < 0) {
            _LOG_E("send to target failed");
            return -1;
        }
        _LOG("send to target ok.");
        assert(rt == payload_len);

        remaining = remaining - payload_len;
        assert(remaining >= 0);
    }
    return 0;
}

/**
 * @brief
 *
 * @param recv_fd
 * @param send_fd
 * @param pipe
 * @param server
 * @param ssb
 * @param src 0: front, 1: backend
 */
static void recv_and_send(int recv_fd, int send_fd, sspipe_t* pipe, sstcp_server_t* server, ssbuffer_t* ssb, int src) {
    char buffer[PACKET_HEAD_LEN + MAX_PAYLOAD_LEN] = {0};
    // 读取客户端数据
    int rlen = 0;
    int rt = 0;
    while (server->running) {
        rlen = sstcp_receive(recv_fd, buffer, sizeof(buffer));
        if (rlen <= 0) {
            perror("recv failed");
            break;
        }
        _LOG("Received: %d", rlen);

        int is_pack = 0;
        if ((pipe->conf->mode == SSPIPE_MODE_LOCAL && src == 0) ||
            (pipe->conf->mode == SSPIPE_MODE_REMOTE && src == 1)) {
            is_pack = 1;
        }

        if (is_pack) {
            rt = pack_send(send_fd, buffer, rlen);
            if (rt == -1) {
                _LOG_E("pack_send error.");
                break;
            } else if (rt == 1) {
                _LOG("need more data.");
                continue;
            }
        } else {
            rt = ssbuffer_grow(ssb, rlen);
            if (rt != _OK) {
                _LOG_E("ssbuffer_grow failed");
                break;
            }
            memcpy(ssb->buf + ssb->len, buffer, rlen);
            ssb->len += rlen;
            rt = unpack_send(pipe, ssb, send_fd);
            if (rt == -1) {
                _LOG_E("unpack_send error.");
                break;
            } else if (rt == 1) {
                _LOG("need more data.");
                continue;
            }
        }
    }
}

#ifdef _WIN32
static DWORD WINAPI backend_thread(LPVOID arg) {
#else
static void* backend_thread(void* arg) {
#endif
    sstcp_client_t* backend = (sstcp_client_t*)(((void**)arg)[0]);
    sspipe_t* pipe = (sspipe_t*)(((void**)arg)[1]);
    int front_fd = (intptr_t)(((void**)arg)[2]);
    assert(front_fd >= 0);
    assert(backend);
    assert(pipe);
    sstcp_server_t* server = (sstcp_server_t*)pipe->server;
    assert(server);

    ssbuffer_t* ssb = ssbuffer_create();
    if (!ssb) {
        perror("create ssbuffer failed");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        return 0;
    }

    recv_and_send(backend->client_fd, front_fd, pipe, server, ssb, 1);

    // char buffer[PACKET_HEAD_LEN + MAX_PAYLOAD_LEN] = {0};
    // // 读取客户端数据
    // int rlen = 0;
    // int rt = 0;
    // while (server->running) {
    //     rlen = sstcp_receive(backend->client_fd, buffer, sizeof(buffer));
    //     if (rlen <= 0) {
    //         perror("recv failed");
    //         break;
    //     }
    //     _LOG("Received: %d", rlen);

    //     if (pipe->conf->mode == SSPIPE_MODE_LOCAL) {
    //         rt = pack_send(server->server_fd, buffer, rlen);
    //         if (rt == -1) {
    //             _LOG_E("pack_send error.");
    //             break;
    //         } else if (rt == 1) {
    //             _LOG("need more data.");
    //             continue;
    //         }
    //     } else if (pipe->conf->mode == SSPIPE_MODE_REMOTE) {
    //         rt = ssbuffer_grow(ssb, rlen);
    //         if (rt != _OK) {
    //             _LOG_E("ssbuffer_grow failed");
    //             break;
    //         }
    //         memcpy(ssb->buf + ssb->len, buffer, rlen);
    //         ssb->len += rlen;
    //         rt = unpack_send(pipe, ssb, server->server_fd);
    //         if (rt == -1) {
    //             _LOG_E("unpack_send error.");
    //             break;
    //         } else if (rt == 1) {
    //             _LOG("need more data.");
    //             continue;
    //         }
    //     } else {
    //         _LOG_E("invalid mode:%d", pipe->conf->mode);
    //         break;
    //     }
    // }

    ssbuffer_free(ssb);
    // sstcp_close(backend->client_fd);
    // sstcp_free_client(backend);
    free(arg);
    return 0;
}

static int run_backend(sspipe_t* pipe, sstcp_client_t* backend, int front_fd) {
    void** arg = (void**)malloc(3 * sizeof(void*));
    arg[0] = (void*)backend;
    arg[1] = (void*)pipe;
    arg[2] = (void*)(intptr_t)front_fd;

#ifdef _WIN32
    HANDLE thread = CreateThread(NULL, 0, backend_thread, arg, 0, NULL);
    if (thread == NULL) {
        perror("Thread creation failed");
        free(arg);
        return _ERR;
    }
#else
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, backend_thread, arg) != 0) {
        perror("Thread creation failed");
        free(arg);
        return _ERR;
    }
    pthread_detach(thread_id);  // 分离线程，避免资源泄漏
#endif

    return _OK;
}

// /**
//  * @brief
//  * @param ssb
//  * @param client
//  * @return 0: ok, 1: need more data (continue), -1: error(break)
//  */
// int handle_remote(ssbuffer_t* ssb, sstcp_client_t* client) {
//     assert(ssb);
//     assert(client);
//     int rt = 0;
//     uint32_t payload_len = 0;
//     int remaining = 0;
//     while (ssb->len > 0) {
//         if (ssb->len < PACKET_HEAD_LEN) return 1;
//         payload_len = ntohl(*(uint32_t*)ssb->buf);
//         if (payload_len > ssb->max_payload || payload_len <= 0) {
//             _LOG_E("payload_len:%d error. max_payload:%d", payload_len, ssb->max_payload);
//             return -1;
//         }
//         if (ssb->len < payload_len + PACKET_HEAD_LEN) return 1;

//         /* TODO: decrypt */

//         rt = sstcp_send(client->client_fd, ssb->buf + 4, payload_len);
//         if (rt < 0) {
//             perror("send to target failed");
//             return -1;
//         }
//         _LOG("send to target ok.");

//         remaining = ssb->len - (payload_len + PACKET_HEAD_LEN);
//         assert(remaining >= 0);
//         if (remaining > 0) {
//             memmove(ssb->buf, ssb->buf + payload_len + PACKET_HEAD_LEN, remaining);
//         }
//         ssb->len = remaining;
//     }
//     return 0;
// }

// /**
//  * @brief
//  * @param ssb
//  * @param client
//  * @return 0: ok, 1: need more data (continue), -1: error(break)
//  */
// int handle_local(sstcp_client_t* backend, const char* buf, int len) {
//     assert(backend);
//     assert(buf);
//     assert(len > 0);

//     int rt = 0;
//     uint32_t payload_len = 0;
//     int remaining = len;
//     while (remaining > 0) {
//         /* TODO: encrypt */

//         // pack and send
//         payload_len = remaining > MAX_PAYLOAD_LEN ? MAX_PAYLOAD_LEN : remaining;
//         uint32_t payload_len_net = htonl(payload_len);
//         rt = sstcp_send(backend->client_fd, (char*)&payload_len_net, PACKET_HEAD_LEN);
//         if (rt < 0) {
//             _LOG_E("send to target failed");
//             return -1;
//         }
//         rt = sstcp_send(backend->client_fd, buf - (len - remaining), payload_len);
//         if (rt < 0) {
//             _LOG_E("send to target failed");
//             return -1;
//         }
//         _LOG("send to target ok.");
//         assert(rt == payload_len);

//         remaining = remaining - payload_len;
//         assert(remaining >= 0);
//     }
//     return 0;
// }

void handle_client(int front_fd, sstcp_server_t* server) {
    assert(front_fd >= 0);
    assert(server);
    sspipe_t* pipe = (sspipe_t*)server->user_data;
    assert(pipe);

    _LOG("handle_client accept: %d", front_fd);
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

    rt = run_backend(pipe, backend, front_fd);
    if (rt != _OK) {
        _LOG_E("run backend failed.");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        return;
    }

    ssbuffer_t* ssb = ssbuffer_create();
    if (!ssb) {
        perror("create ssbuffer failed");
        sstcp_close(backend->client_fd);
        sstcp_free_client(backend);
        return;
    }
    recv_and_send(front_fd, backend->client_fd, pipe, server, ssb, 0);

    // char buffer[PACKET_HEAD_LEN + MAX_PAYLOAD_LEN] = {0};
    // // 读取客户端数据
    // int rlen = 0;
    // while (server->running) {
    //     rlen = sstcp_receive(front_fd, buffer, sizeof(buffer));
    //     if (rlen <= 0) {
    //         perror("recv failed");
    //         break;
    //     }
    //     _LOG("Received: %d", rlen);

    //     rt = ssbuffer_grow(ssb, rlen);
    //     if (rt != _OK) {
    //         _LOG_E("ssbuffer_grow failed");
    //         break;
    //     }
    //     memcpy(ssb->buf + ssb->len, buffer, rlen);
    //     ssb->len += rlen;

    //     if (pipe->conf->mode == SSPIPE_MODE_LOCAL) {
    //         rt = handle_local(backend, buffer, rlen);
    //         if (rt == -1) {
    //             _LOG_E("handle_remote error.");
    //             break;
    //         } else if (rt == 1) {
    //             _LOG("need more data.");
    //             continue;
    //         }
    //     } else if (pipe->conf->mode == SSPIPE_MODE_REMOTE) {
    //         rt = handle_remote(ssb, backend);
    //         if (rt == -1) {
    //             _LOG_E("handle_remote error.");
    //             break;
    //         } else if (rt == 1) {
    //             _LOG("need more data.");
    //             continue;
    //         }
    //     } else {
    //         _LOG_E("invalid mode:%d", pipe->conf->mode);
    //         break;
    //     }
    // }

    ssbuffer_free(ssb);
    sstcp_close(backend->client_fd);
    sstcp_free_client(backend);
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
