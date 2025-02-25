#include "sspipe.h"

#include "ssqueue.h"

// ssbuffer start

ssbuffer_t* ssbuffer_init() {
    ssbuffer_t* ssb = (ssbuffer_t*)calloc(1, sizeof(ssbuffer_t));
    if (!ssb) {
        return NULL;
    }
    return ssb;
}

void ssbuffer_free(ssbuffer_t* ssb) {
    if (ssb) {
        if (ssb->buf) {
            free(ssb->buf);
            ssb->buf = NULL;
        }
        free(ssb);
    }
}

int ssbuffer_grow(ssbuffer_t* ssb, int len) {
    assert(len >= 0);
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

// ssbuffer end

// connection start

static ssconn_t* g_conn_tb = NULL;

static int real_close(ssconn_t* conn) {
    assert(conn);
    assert(conn->fd > 0);
    ssnet_t* net = conn->net;
    assert(net);
    conn->status = PCONN_ST_OFF;
    ssnet_tcp_close(net, conn->fd);
    _LOG("real_close ok. fd:%d", conn->fd);
    return _OK;
}

ssconn_t* ssconn_init(int fd, int cp_fd, ssconn_type_t type, ssconn_st_t status, ssnet_t* net) {
    ssconn_t* conn = (ssconn_t*)calloc(1, sizeof(ssconn_t));
    if (!conn) {
        return NULL;
    }
    conn->fd = fd;
    conn->cp_fd = cp_fd;
    conn->type = type;
    conn->status = status;
    conn->net = net;
    conn->recv_buf = ssbuffer_init();
    conn->send_buf = ssbuffer_init();
    HASH_ADD_INT(g_conn_tb, fd, conn);
    return conn;
}

ssconn_t* ssconn_get(int fd) {
    ssconn_t* conn = NULL;
    HASH_FIND_INT(g_conn_tb, &fd, conn);
    return conn;
}

void ssconn_free(ssconn_t* conn) {
    if (conn) {
        if (conn->recv_buf) {
            ssbuffer_free(conn->recv_buf);
            conn->recv_buf = NULL;
        }
        if (conn->send_buf) {
            ssbuffer_free(conn->send_buf);
            conn->send_buf = NULL;
        }
        if (g_conn_tb) {
            HASH_DEL(g_conn_tb, conn);
        }
        free(conn);
    }
}

void ssconn_free_all() {
    _LOG("ssconn_free_all start. g_conn_tb:%p", g_conn_tb);
    if (g_conn_tb) {
        ssconn_t *conn, *tmp;
        HASH_ITER(hh, g_conn_tb, conn, tmp) {
            real_close(conn);
            ssconn_free(conn);
        }
        g_conn_tb = NULL;
    }
    _LOG("ssconn_free_all ok.");
}

int ssconn_close(int fd) {
    _LOG("ssconn_close fd:%d", fd);
    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG("ssconn_close ssconn_get conn error fd:%d", fd);
        return _ERR;
    }
    conn->status = PCONN_ST_OFF;
    int cp_fd = conn->cp_fd;
    ssconn_t* cp_conn = ssconn_get(cp_fd);
    if (!cp_conn) {
        _LOG("ssconn_close ssconn_get cp_conn error fd:%d", cp_fd);
        assert(0); /* TODO: debug */
        return _ERR;
    }
    cp_conn->status = PCONN_ST_OFF;
    real_close(conn);
    ssconn_free(conn);
    real_close(cp_conn);
    ssconn_free(cp_conn);
    _LOG("ssconn_close couple fd:%d cp_fd:%d", fd, cp_fd);
    return _OK;
}

int ssconn_flush_send_buf(ssconn_t* cp_conn) {
    if (cp_conn->send_buf->len > 0) {
        int rt = ssnet_tcp_send(cp_conn->net, cp_conn->fd, cp_conn->send_buf->buf, cp_conn->send_buf->len);
        assert(rt <= cp_conn->send_buf->len);
        if (rt < 0) {
            // error or closed
            _LOG_W("ssconn_flush_send_buf error or closed fd:%d", cp_conn->fd);
            ssconn_close(cp_conn->fd);
            return _ERR;
        }
        if (rt == 0) {
            _LOG_W("ssconn_flush_send_buf pending fd:%d", cp_conn->cp_fd);
            return _OK;
        }
        if (rt != cp_conn->send_buf->len) {
            _LOG_W("ssnet_tcp_send remain. fd:%d", cp_conn->cp_fd);
            memmove(cp_conn->send_buf->buf, cp_conn->send_buf->buf + rt, cp_conn->send_buf->len - rt);
            cp_conn->send_buf->len -= rt;
            assert(cp_conn->send_buf->len >= 0);
            return _OK;
        }
        cp_conn->send_buf->len = 0;
    }
    return _OK;
}

// connection end

//  ---------- sspipe start -----------

// callback start

#define _GET_SSPIPE_FROM_NET                               \
    sspipe_t* sspipe = (sspipe_t*)ssnet_get_userdata(net); \
    assert(sspipe)

static char packet_tag[] = {'S', 'S', 'P'};

static int on_recv(ssnet_t* net, int fd, const char* buf, int len) {
    _LOG("sspipe on_recv fd:%d len:%d", fd, len);
    _GET_SSPIPE_FROM_NET;
    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG_E("on_recv ssconn_get conn error");
        return _ERR;
    }
    assert(conn->cp_fd > 0);

    ssconn_t* cp_conn = ssconn_get(conn->cp_fd);
    if (!cp_conn) {
        _LOG_E("on_recv ssconn_get cp_conn error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    assert(cp_conn->cp_fd > 0);

    if (conn->status == PCONN_ST_OFF) {
        _LOG_W("on_recv conn is closed fd:%d", conn->fd);
        ssconn_close(conn->fd);
        return _ERR;
    }
    if (cp_conn->status == PCONN_ST_OFF) {
        _LOG_W("on_recv cp_conn is closedfd:%d", cp_conn->fd);
        ssconn_close(cp_conn->cp_fd);
        return _ERR;
    }

    assert(conn->fd == cp_conn->cp_fd && cp_conn->fd == conn->cp_fd);
    assert(conn->recv_buf);
    assert(conn->send_buf);
    assert(cp_conn->recv_buf);
    assert(cp_conn->send_buf);

    int rt = ssbuffer_grow(conn->recv_buf, len);
    if (rt != _OK) {
        _LOG_E("on_recv ssbuffer_grow recv_buf error");
        ssconn_close(conn->fd);
        return _ERR;
    }
    memcpy(conn->recv_buf->buf + conn->recv_buf->len, buf, len);
    conn->recv_buf->len += len;
    assert(conn->recv_buf->len > 0);

    if (conn->status != PCONN_ST_ON || cp_conn->status != PCONN_ST_ON) {
        _LOG_W("on_recv conn status not ON");
        return _ERR;
    }

    rt = ssconn_flush_send_buf(cp_conn);
    if (rt != _OK) {
        _LOG_E("on_recv ssconn_flush_send_buf error");
        return _ERR;
    }

    int is_pack = (sspipe->config->mode == SSPIPE_MODE_LOCAL && conn->type == SSCONN_TYPE_SERV) ||
                  (sspipe->config->mode == SSPIPE_MODE_REMOTE && conn->type == SSCONN_TYPE_CLI);

    if (is_pack) {
        int rt = ssbuffer_grow(conn->recv_buf, sizeof(packet_tag));
        if (rt != _OK) {
            _LOG_E("on_recv ssbuffer_grow recv_buf error");
            ssconn_close(conn->fd);
            return _ERR;
        }
        memcpy(conn->recv_buf->buf + conn->recv_buf->len, packet_tag, sizeof(packet_tag));
        conn->recv_buf->len += sizeof(packet_tag);
        assert(conn->recv_buf->len > 0);

        // encrypt
        int ciphertext_len = 0;
        char* cipher_text = aes_encrypt(sspipe->config->key, conn->recv_buf->buf, conn->recv_buf->len, &ciphertext_len);
        if (cipher_text == NULL) {
            _LOG_E("on_recv aes_encrypt error");
            ssconn_close(conn->fd);
            return _ERR;
        }

        // pack and send to buffer
        rt = ssbuffer_grow(cp_conn->send_buf, ciphertext_len + PACKET_HEAD_LEN + sizeof(packet_tag));
        if (rt != _OK) {
            _LOG_E("on_recv ssbuffer_grow send_buf error");
            ssconn_close(conn->fd);
            return _ERR;
        }
        int ciphertext_len_net = htonl(ciphertext_len);
        memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, &ciphertext_len_net, PACKET_HEAD_LEN);
        cp_conn->send_buf->len += PACKET_HEAD_LEN;
        memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, cipher_text, ciphertext_len);
        cp_conn->send_buf->len += ciphertext_len;
        free(cipher_text);

        conn->recv_buf->len = 0;

        rt = ssconn_flush_send_buf(cp_conn);
        if (rt != _OK) {
            _LOG_E("on_recv pack ssconn_flush_send_buf error");
            return _ERR;
        }
    } else {
        int ciphertext_len = 0;
        int plain_text_len = 0;
        char* plain_text = NULL;
        while (conn->recv_buf->len > PACKET_HEAD_LEN) {
            // unpack
            ciphertext_len = ntohl(*(int*)conn->recv_buf->buf);
            if (ciphertext_len <= 0 || ciphertext_len > 65535) { /* TODO: magic number */
                _LOG_E("on_recv ciphertext_len:%d error. recv_buf->len:%d", ciphertext_len, conn->recv_buf->len);
                ssconn_close(conn->fd);
                return _ERR;
            }
            if (ciphertext_len > conn->recv_buf->len - PACKET_HEAD_LEN) {
                _LOG("on_recv ciphertext_len:%d > recv_buf->len:%d rfd:%d sfd:%d", ciphertext_len, conn->recv_buf->len,
                     conn->fd, conn->cp_fd);
                return _OK;
            }
            // decrypt
            plain_text = aes_decrypt(sspipe->config->key, conn->recv_buf->buf + PACKET_HEAD_LEN, ciphertext_len,
                                     &plain_text_len);
            if (plain_text == NULL) {
                _LOG_E("on_recv aes_decrypt error");
                ssconn_close(conn->fd);
                return _ERR;
            }

            assert(plain_text_len > sizeof(packet_tag));

            // check packet tag
            if (memcmp(plain_text + plain_text_len - sizeof(packet_tag), packet_tag, sizeof(packet_tag)) != 0) {
                _LOG_E("on_recv packet_tag error");
                ssconn_close(conn->fd);
                return _ERR;
            }

            // send to buffer
            rt = ssbuffer_grow(cp_conn->send_buf, plain_text_len - sizeof(packet_tag));
            if (rt != _OK) {
                _LOG_E("on_recv ssbuffer_grow send_buf error");
                ssconn_close(conn->fd);
                return _ERR;
            }
            memcpy(cp_conn->send_buf->buf + cp_conn->send_buf->len, plain_text, plain_text_len - sizeof(packet_tag));
            cp_conn->send_buf->len += plain_text_len - sizeof(packet_tag);
            free(plain_text);

            memmove(conn->recv_buf->buf, conn->recv_buf->buf + PACKET_HEAD_LEN + ciphertext_len,
                    conn->recv_buf->len - PACKET_HEAD_LEN - ciphertext_len);
            conn->recv_buf->len -= PACKET_HEAD_LEN + ciphertext_len;
            assert(conn->recv_buf->len >= 0);

            rt = ssconn_flush_send_buf(cp_conn);
            if (rt != _OK) {
                _LOG_E("on_recv unpack ssconn_flush_send_buf error");
                return _ERR;
            }
        }
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
    _GET_SSPIPE_FROM_NET;

    int back_fd = 0;
    ssconn_t* front_conn = NULL;
    ssconn_t* back_conn = NULL;
    back_fd = ssnet_tcp_connect(sspipe->net, sspipe->config->target_ip, sspipe->config->target_port);
    _LOG("connect back_fd:%d serv_fd:%d", back_fd, serv_fd);
    if (back_fd <= 0) {
        _LOG_E("on_accept connect back_fd:%d serv_fd:%d error", back_fd, serv_fd);
        ssnet_tcp_close(sspipe->net, serv_fd);
        return _ERR;
    }

    // ssconn_close_all();
    // debug
    assert(ssconn_get(serv_fd) == NULL);
    assert(ssconn_get(back_fd) == NULL);

    front_conn = ssconn_init(serv_fd, back_fd, SSCONN_TYPE_SERV, PCONN_ST_WAIT, sspipe->net);
    if (!front_conn) {
        _LOG_E("on_accept ssconn_init front_conn error fd:%d", serv_fd);
        ssnet_tcp_close(sspipe->net, serv_fd);
        ssnet_tcp_close(sspipe->net, back_fd);
        return _ERR;
    }
    back_conn = ssconn_init(back_fd, serv_fd, SSCONN_TYPE_CLI, PCONN_ST_WAIT, sspipe->net);
    if (!back_conn) {
        _LOG_E("on_accept ssconn_init back_conn error fd:%d", back_fd);
        ssnet_tcp_close(sspipe->net, serv_fd);
        ssnet_tcp_close(sspipe->net, back_fd);
        ssconn_free(front_conn);
        return _ERR;
    }
    return _OK;
}

static int on_back_connected(sspipe_t* sspipe, ssconn_t* back_conn) {
    assert(back_conn);
    assert(back_conn->cp_fd > 0);
    _LOG("on_connected fd:%d", back_conn->fd);
    ssconn_t* front_conn = ssconn_get(back_conn->cp_fd);
    if (!front_conn || front_conn->status == PCONN_ST_OFF) {
        _LOG_E("on_back_connected ssconn_get front_conn error fd:%d", back_conn->cp_fd);
        ssconn_close(back_conn->fd);
        return _ERR;
    }
    front_conn->status = PCONN_ST_ON;
    back_conn->status = PCONN_ST_ON;
    if (front_conn->recv_buf->len > 0) {
        on_recv(sspipe->net, front_conn->fd, NULL, 0);
    }

    return _OK;
}

static int on_back_writable(ssnet_t* net, int fd) {
    _LOG("on_writable fd:%d", fd);
    _GET_SSPIPE_FROM_NET;
    ssconn_t* back_conn = ssconn_get(fd);
    if (!back_conn) {
        _LOG_E("on_back_writable ssconn_get back_conn error fd:%d", fd);
        return _ERR;
    }
    if (back_conn->type != SSCONN_TYPE_CLI) {
        return _OK;
    }
    int rt = on_back_connected(sspipe, back_conn);
    return rt;
}

static int on_update(ssev_loop_t* loop, void* ud) {
    // ssnet_t* net = (ssnet_t*)ud;
    // assert(net);
    // _GET_SSPIPE_FROM_NET;

    // _LOG("on_update start queue len:%d", g_close_fd_queue ? g_close_fd_queue->size : 0);
    // ssconn_close_all();

    // _LOG("on_update end queue len:%d", g_close_fd_queue ? g_close_fd_queue->size : 0);
    return _OK;
}

// callback end

sspipe_t* sspipe_init(ssev_loop_t* loop, ssconfig_t* config) {
    sspipe_t* sspipe = calloc(1, sizeof(sspipe_t));
    if (sspipe == NULL) {
        return NULL;
    }
    sspipe->config = config;
    sspipe->net = ssnet_init(loop, config->read_buf_size);
    if (sspipe->net == NULL) {
        free(sspipe);
        return NULL;
    }
    ssnet_set_userdata(sspipe->net, sspipe);
    ssnet_set_recv_cb(sspipe->net, on_recv);
    ssnet_set_close_cb(sspipe->net, on_close);
    ssnet_set_writable_cb(sspipe->net, on_back_writable);
    ssev_set_update_cb(loop, on_update);

    sspipe->listen_fd = ssnet_tcp_init_server(sspipe->net, config->listen_ip, config->listen_port, on_accept);
    if (sspipe->listen_fd <= 0) {
        sspipe_free(sspipe);
        return NULL;
    }
    return sspipe;
}

void sspipe_free(sspipe_t* sspipe) {
    if (sspipe) {
        if (sspipe->listen_fd > 0) {
            ssnet_tcp_stop_server(sspipe->net, sspipe->listen_fd);
        }
        ssconn_free_all();
        if (sspipe->net) {
            ssnet_free(sspipe->net);
        }
        free(sspipe);
        _LOG("sspipe_free ok.");
    }
    return;
}

//  ---------- sspipe end -----------