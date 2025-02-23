#include "ssremote.h"

//  ---------- callback start -----------

#define _GET_SSREMOTE_FROM_NET                                   \
    ssremote_t* ssremote = (ssremote_t*)ssnet_get_userdata(net); \
    assert(ssremote)

static int on_recv(ssnet_t* net, int fd, const char* buf, int len) {
    _LOG("sspipe on_recv fd:%d len:%d", fd, len);
    _GET_SSREMOTE_FROM_NET;
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

    ssconn_t* cp_conn = ssconn_get(conn->cp_fd);
    if (!cp_conn) {
        _LOG_E("ssconn_get cp_conn error");
        ssconn_close(conn->fd);
        return _ERR;
    }

    if (conn->status != PCONN_ST_ON || cp_conn->status != PCONN_ST_ON) {
        _LOG_E("conn status error");
        return _ERR;
    }

    int rt = 0;
    if (conn->type == SSCONN_TYPE_CLI) {
        // encrypt
        int ciphertext_len = 0;
        char* cipher_text = aes_encrypt(ssremote->config->key, buf, len, &ciphertext_len);
        if (cipher_text == NULL) {
            _LOG_E("aes_encrypt error");
            ssconn_close(conn->fd);
            return _ERR;
        }

        // pack and send to buffer
        rt = ssbuffer_grow(cp_conn->send_buf, ciphertext_len + PACKET_HEAD_LEN);
        if (rt != _OK) {
            _LOG_E("ssbuffer_grow send_buf error");
            return _ERR;
        }
        int ciphertext_len_net = htonl(ciphertext_len);
        memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, &ciphertext_len_net, PACKET_HEAD_LEN);
        cp_conn->send_buf->len += PACKET_HEAD_LEN;
        memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, cipher_text, ciphertext_len);
        cp_conn->send_buf->len += ciphertext_len;
        free(cipher_text);
    } else if (conn->type == SSCONN_TYPE_SERV) {
        rt = ssbuffer_grow(conn->recv_buf, len);
        if (rt != _OK) {
            _LOG_E("ssbuffer_grow recv_buf error");
            return _ERR;
        }
        memcpy(conn->recv_buf->buf + conn->recv_buf->len, buf, len);
        conn->recv_buf->len += len;

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
                _LOG("ciphertext_len:%d > recv_buf->len:%d", ciphertext_len, conn->recv_buf->len);
                return _OK;
            }
            // decrypt
            plain_text = aes_decrypt(ssremote->config->key, conn->recv_buf->buf + PACKET_HEAD_LEN, ciphertext_len, &plain_text_len);
            if (plain_text == NULL) {
                _LOG_E("aes_decrypt error");
                ssconn_close(conn->fd);
                return _ERR;
            }

            // send to buffer
            rt = ssbuffer_grow(cp_conn->send_buf, plain_text_len);
            if (rt != _OK) {
                _LOG_E("ssbuffer_grow send_buf error");
                return _ERR;
            }
            memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, plain_text, plain_text_len);
            cp_conn->send_buf->len += plain_text_len;
            free(plain_text);
            memmove(conn->recv_buf->buf, conn->recv_buf->buf + PACKET_HEAD_LEN + ciphertext_len, conn->recv_buf->len - PACKET_HEAD_LEN - ciphertext_len);
            conn->recv_buf->len -= PACKET_HEAD_LEN + ciphertext_len;
            assert(conn->recv_buf->len >= 0);
        }
    } else {
        _LOG_E("conn type error");
        return _ERR;
    }
    if (cp_conn->send_buf->len > 0) {
        rt = ssnet_tcp_send(net, cp_conn->fd, cp_conn->send_buf->buf, cp_conn->send_buf->len);
        assert(rt <= cp_conn->send_buf->len);
        if (rt < 0) {
            // error or closed
            _LOG_E("ssnet_tcp_send error or closed fd:%d", conn->cp_fd);
            ssconn_close(conn->fd);
            return _ERR;
        }
        if (rt == 0) {
            _LOG_E("ssnet_tcp_send pending fd:%d", conn->cp_fd);
            return _OK;
        }
        if (rt != cp_conn->send_buf->len) {
            _LOG_E("ssnet_tcp_send remain. fd:%d", conn->cp_fd);
            memmove(cp_conn->send_buf->buf, cp_conn->send_buf->buf + rt, cp_conn->send_buf->len - rt);
            cp_conn->send_buf->len -= rt;
            assert(cp_conn->send_buf->len >= 0);
            return _OK;
        }
        cp_conn->send_buf->len = 0;
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
    _GET_SSREMOTE_FROM_NET;

    int back_fd = -1;
    ssconn_t* front_conn = NULL;
    ssconn_t* back_conn = NULL;
    back_fd = ssnet_tcp_connect(ssremote->net, ssremote->config->target_ip, ssremote->config->target_port);
    _LOG("connect back_fd:%d serv_fd:%d", back_fd, serv_fd);
    if (back_fd <= 0) {
        _LOG_E("connect back_fd:%d serv_fd:%d error", back_fd, serv_fd);
        goto _on_accept_error;
    }
    front_conn = ssconn_init(serv_fd, back_fd, SSCONN_TYPE_SERV, PCONN_ST_WAIT, ssremote->net);
    if (!front_conn) {
        _LOG_E("ssconn_init front_conn error");
        goto _on_accept_error;
    }
    back_conn = ssconn_init(back_fd, serv_fd, SSCONN_TYPE_CLI, PCONN_ST_WAIT, ssremote->net);
    if (!back_conn) {
        _LOG_E("ssconn_init back_conn error");
        goto _on_accept_error;
    }
    return _OK;

_on_accept_error:
    if (back_fd > 0) {
        ssnet_tcp_close(ssremote->net, back_fd);
    }
    if (front_conn) {
        ssconn_free(front_conn);
    }
    if (back_conn) {
        ssconn_free(back_conn);
    }
    return _ERR;
}

static int on_back_connected(ssremote_t* ssremote, ssconn_t* back_conn) {
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
        on_recv(ssremote->net, front_conn->fd, NULL, 0); /* TODO: */
    }

    return _OK;
}

static int on_back_writable(ssnet_t* net, int fd) {
    _LOG("on_writable fd:%d", fd);
    _GET_SSREMOTE_FROM_NET;
    ssconn_t* back_conn = ssconn_get(fd);
    if (!back_conn) {
        _LOG_E("ssconn_get back_conn error");
        return _ERR;
    }
    if (back_conn->type != SSCONN_TYPE_CLI) {
        return _OK;
    }
    int rt = on_back_connected(ssremote, back_conn);
    return rt;
}

static int on_update(ssev_loop_t* loop, void* ud) {
    // ssnet_t* net = (ssnet_t*)ud;
    // assert(net);
    // _GET_SSREMOTE_FROM_NET;
    ssconn_close_all();
    return _OK;
}

//  ---------- callback end -----------

ssremote_t* ssremote_init(ssev_loop_t* loop, ssconfig_t* config) {
    ssremote_t* ssremote = calloc(1, sizeof(ssremote_t));
    if (ssremote == NULL) {
        return NULL;
    }
    ssremote->config = config;
    ssremote->net = ssnet_init(loop, config->read_buf_size);
    if (ssremote->net == NULL) {
        free(ssremote);
        return NULL;
    }
    ssnet_set_userdata(ssremote->net, ssremote);
    ssnet_set_recv_cb(ssremote->net, on_recv);
    ssnet_set_close_cb(ssremote->net, on_close);
    ssnet_set_writable_cb(ssremote->net, on_back_writable);
    ssev_set_update_cb(loop, on_update);

    ssremote->listen_fd = ssnet_tcp_init_server(ssremote->net, config->listen_ip, config->listen_port, on_accept);
    if (ssremote->listen_fd <= 0) {
        ssremote_free(ssremote);
        return NULL;
    }
    return ssremote;
}

void ssremote_free(ssremote_t* ssremote) {
    if (ssremote) {
        if (ssremote->listen_fd > 0) {
            ssnet_tcp_stop_server(ssremote->net, ssremote->listen_fd);
        }
        if (ssremote->net) {
            ssnet_free(ssremote->net);
        }
        free(ssremote);
    }
    ssconn_free_all();
    return;
}
