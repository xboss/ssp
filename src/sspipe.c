#include "sspipe.h"

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

// connection
int ssconn_close(int fd) {
    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG("ssconn_get conn error");
        return _ERR;
    }
    ssnet_t* net = conn->net;
    assert(net);
    conn->status = PCONN_ST_OFF;
    ssnet_tcp_close(net, fd);
    int cp_fd = conn->cp_fd;
    ssconn_free(conn);
    ssconn_t* cp_conn = ssconn_get(cp_fd);
    if (!cp_conn) {
        _LOG("ssconn_get cp_conn error");
        return _ERR;
    }
    ssnet_tcp_close(net, cp_fd);
    cp_conn->status = PCONN_ST_OFF;
    ssconn_free(cp_conn);
    return _OK;
}