#include "sspipe.h"

#include <arpa/inet.h>
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

/* ---------- callback ----------- */

void handle_client(int client_socket, sstcp_server_t* server) {
    assert(client_socket >= 0);
    assert(server);
    sspipe_t* pipe = (sspipe_t*)server->user_data;
    assert(pipe);

    char buffer[1024] = {0};
    // char* hello = "Hello from server";

    // 读取客户端数据
    int valread = 0;
    while (server->running) {
        valread = sstcp_receive(client_socket, buffer, 1024);
        if (valread > 0) {
            _LOG("Received: %s", buffer);
            // 发送响应
            // sstcp_send(client_socket, hello, strlen(hello));
            sstcp_send(client_socket, buffer, valread);
            _LOG("Hello message sent to client");
        } else {
            perror("recv failed");
            // sstcp_close(client_socket);
            break;
        }
    }

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
