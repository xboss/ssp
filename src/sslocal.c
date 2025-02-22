#include "sslocal.h"

//  ---------- callback start -----------

#define _GET_SSLOCAL_FROM_NET                                 \
    sslocal_t* sslocal = (sslocal_t*)ssnet_get_userdata(net); \
    assert(sslocal)

static int on_recv(ssnet_t* net, int fd, const char* buf, int len) {
    _LOG("sspipe on_recv fd:%d len:%d", fd, len);
    _GET_SSLOCAL_FROM_NET;
    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG_E("ssconn_get conn error");
        return _ERR;
    }
    assert(conn->cp_fd > 0);
    if (conn->status == PCONN_ST_OFF) {
        _LOG_E("conn is closed");
        ssconn_close(conn->cp_fd);
        return _ERR;
    }
    assert(conn->recv_buf);
    assert(conn->send_buf);
    int rt = ssbuffer_grow(conn->recv_buf, len);
    if (rt != _OK) {
        _LOG_E("ssbuffer_grow error");
        return _ERR;
    }
    memcpy(conn->recv_buf->buf + conn->recv_buf->len, buf, len);
    conn->recv_buf->len += len;

    if (conn->status != PCONN_ST_ON) {
        _LOG_E("conn status error");
        return _ERR;
    }

    if (conn->type == SSCONN_TYPE_SERV) {
        if (conn->recv_buf->len <= 0) {
            return _OK;
        }
        // encrypt
        int ciphertext_len = 0;
        char* cipher_text = aes_encrypt(sslocal->config->key, conn->recv_buf->buf, conn->recv_buf->len, &ciphertext_len);
        if (cipher_text == NULL) {
            _LOG_E("aes_encrypt error");
            ssconn_close(conn->fd);
            return _ERR;
        }
        // pack
        char* packet = (char*)calloc(1, PACKET_HEAD_LEN + ciphertext_len);
        if (packet == NULL) {
            _LOG_E("calloc error");
            free(cipher_text);
            ssconn_close(conn->fd);
            return _ERR;
        }
        int ciphertext_len_net = htonl(ciphertext_len);
        memcpy(packet, &ciphertext_len_net, PACKET_HEAD_LEN);
        memcpy(packet + PACKET_HEAD_LEN, cipher_text, ciphertext_len);
        // send
        rt = ssnet_tcp_send(net, conn->cp_fd, packet, PACKET_HEAD_LEN + ciphertext_len);
        assert(rt <= PACKET_HEAD_LEN + ciphertext_len);
        if (rt < 0) {
            // error or closed
            _LOG_E("ssnet_tcp_send error");
            free(cipher_text);
            free(packet);
            ssconn_close(conn->fd);
            return _ERR;
        }
        if (rt == 0) {
            _LOG_E("ssnet_tcp_send pending");
            free(cipher_text);
            free(packet);
            return _ERR;
        }
        if (rt != PACKET_HEAD_LEN + ciphertext_len) {
            _LOG_E("ssnet_tcp_send error");
            free(cipher_text);
            free(packet);
            memmove(conn->recv_buf->buf, conn->recv_buf->buf + rt, conn->recv_buf->len - rt);
            conn->recv_buf->len -= rt;
            return _ERR;
        }
        free(packet);
        free(cipher_text);
    } else if (conn->type == SSCONN_TYPE_CLI) {
        int ciphertext_len = 0;
        int plain_text_len = 0;
        char* plain_text = NULL;
        while (conn->recv_buf->len > PACKET_HEAD_LEN) {
            // unpack
            ciphertext_len = ntohl(*(int*)conn->recv_buf->buf);
            if (ciphertext_len <= 0 || ciphertext_len > 65535) { /* TODO: magic number */
                _LOG_E("ciphertext_len:%d error. recv_buf->len:%d", ciphertext_len, conn->recv_buf->len);
                ssconn_close(conn->fd);
                return _ERR;
            }
            if (ciphertext_len > conn->recv_buf->len - PACKET_HEAD_LEN) {
                _LOG_E("ciphertext_len:%d > recv_buf->len:%d", ciphertext_len, conn->recv_buf->len);
                return _ERR;
            }
            // decrypt
            plain_text = aes_decrypt(sslocal->config->key, conn->recv_buf->buf + PACKET_HEAD_LEN, ciphertext_len, &plain_text_len);
            if (plain_text == NULL) {
                _LOG_E("aes_decrypt error");
                ssconn_close(conn->fd);
                return _ERR;
            }
            // send
            rt = ssnet_tcp_send(net, conn->cp_fd, plain_text, plain_text_len);
            assert(rt <= plain_text_len);
            if (rt < 0) {
                // error or closed
                _LOG_E("ssnet_tcp_send error");
                free(plain_text);
                ssconn_close(conn->fd);
                return _ERR;
            }
            if (rt == 0) {
                _LOG_E("ssnet_tcp_send pending");
                free(plain_text);
                return _ERR;
            }
            free(plain_text);
            memmove(conn->recv_buf->buf, conn->recv_buf->buf + PACKET_HEAD_LEN + ciphertext_len, conn->recv_buf->len - PACKET_HEAD_LEN - ciphertext_len);
            conn->recv_buf->len -= PACKET_HEAD_LEN + ciphertext_len;
            assert(conn->recv_buf->len >= 0);
        }
    } else {
        _LOG_E("conn type error");
        return _ERR;
    }
    return _OK;
}

static int on_close(ssnet_t* net, int fd) {
    _LOG("on close fd:%d", fd);
    int rt = ssconn_close(fd);
    return rt;
}

static int on_accept(ssnet_t* net, int serv_fd) {
    _LOG("on_accept serv_fd:%d", serv_fd);
    _GET_SSLOCAL_FROM_NET;

    int back_fd = -1;
    ssconn_t* front_conn = NULL;
    ssconn_t* back_conn = NULL;
    back_fd = ssnet_tcp_connect(sslocal->net, sslocal->config->target_ip, sslocal->config->target_port);
    _LOG("connect back_fd:%d serv_fd:%d", back_fd, serv_fd);
    if (back_fd <= 0) {
        _LOG_E("connect back_fd:%d serv_fd:%d error", back_fd, serv_fd);
        goto _on_accept_error;
    }
    front_conn = ssconn_init(serv_fd, back_fd, SSCONN_TYPE_SERV, PCONN_ST_WAIT, sslocal->net);
    if (!front_conn) {
        _LOG_E("ssconn_init front_conn error");
        goto _on_accept_error;
    }
    back_conn = ssconn_init(back_fd, serv_fd, SSCONN_TYPE_CLI, PCONN_ST_WAIT, sslocal->net);
    if (!back_conn) {
        _LOG_E("ssconn_init back_conn error");
        goto _on_accept_error;
    }
    return _OK;

_on_accept_error:
    if (back_fd > 0) {
        ssnet_tcp_close(sslocal->net, back_fd);
    }
    if (front_conn) {
        ssconn_free(front_conn);
    }
    if (back_conn) {
        ssconn_free(back_conn);
    }
    return _ERR;
}

static int on_back_connected(sslocal_t* sslocal, ssconn_t* back_conn) {
    assert(back_conn);
    assert(back_conn->cp_fd > 0);
    _LOG("on_connected fd:%d", back_conn->fd);
    ssconn_t* front_conn = ssconn_get(back_conn->cp_fd);
    if (!front_conn || front_conn->status == PCONN_ST_OFF) {
        _LOG_E("ssconn_get front_conn error");
        ssconn_close(back_conn->fd);
        return _ERR;
    }
    front_conn->status = PCONN_ST_ON;
    back_conn->status = PCONN_ST_ON;
    if (front_conn->recv_buf->len > 0) {
        on_recv(sslocal->net, front_conn->fd, NULL, 0);
    }

    return _OK;
}

static int on_back_writable(ssnet_t* net, int fd) {
    _LOG("on_writable fd:%d", fd);
    _GET_SSLOCAL_FROM_NET;
    ssconn_t* back_conn = ssconn_get(fd);
    if (!back_conn) {
        _LOG_E("ssconn_get back_conn error");
        return _ERR;
    }
    if (back_conn->type != SSCONN_TYPE_CLI) {
        return _OK;
    }
    int rt = on_back_connected(sslocal, back_conn);
    return rt;
}

static int on_update(ssev_loop_t* loop, void* ud) {
    // ssnet_t* net = (ssnet_t*)ud;
    // assert(net);
    // _GET_SSLOCAL_FROM_NET;
    ssconn_close_all();
    return _OK;
}

//  ---------- callback end -----------

sslocal_t* sslocal_init(ssev_loop_t* loop, ssconfig_t* config) {
    sslocal_t* sslocal = calloc(1, sizeof(sslocal_t));
    if (sslocal == NULL) {
        return NULL;
    }
    sslocal->config = config;
    sslocal->net = ssnet_init(loop, config->read_buf_size);
    if (sslocal->net == NULL) {
        free(sslocal);
        return NULL;
    }
    ssnet_set_userdata(sslocal->net, sslocal);
    ssnet_set_recv_cb(sslocal->net, on_recv);
    ssnet_set_close_cb(sslocal->net, on_close);
    ssnet_set_writable_cb(sslocal->net, on_back_writable);
    ssev_set_update_cb(loop, on_update);

    sslocal->listen_fd = ssnet_tcp_init_server(sslocal->net, config->listen_ip, config->listen_port, on_accept);
    if (sslocal->listen_fd <= 0) {
        sslocal_free(sslocal);
        return NULL;
    }
    return sslocal;
}

void sslocal_free(sslocal_t* sslocal) {
    if (sslocal) {
        if (sslocal->listen_fd > 0) {
            ssnet_tcp_stop_server(sslocal->net, sslocal->listen_fd);
        }
        if (sslocal->net) {
            ssnet_free(sslocal->net);
        }
        free(sslocal);
    }
    return;
}
