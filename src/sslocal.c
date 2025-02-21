#include "sslocal.h"

//  ---------- callback start -----------

#define _GET_SSLOCAL_FROM_NET                                 \
    sslocal_t* sslocal = (sslocal_t*)ssnet_get_userdata(net); \
    assert(sslocal)

static int on_recv(ssnet_t* net, int fd, const char* buf, int len, struct sockaddr* addr) {
    _LOG("sspipe on_recv fd:%d len:%d", fd, len);
    /* TODO: */
    return _OK;
}

static int on_close(ssnet_t* net, int fd) {
    _LOG("on close fd:%d", fd);
    int rt = ssconn_close(fd);
    /* TODO: */
    return rt;
}

static int on_accept(ssnet_t* net, int serv_fd) {
    _LOG("on_accept serv_fd:%d", serv_fd);
    _GET_SSLOCAL_FROM_NET;

    int back_fd = ssnet_tcp_connect(sslocal->net, sslocal->config->target_ip, sslocal->config->target_port);
    _LOG("connect back_fd:%d serv_fd:%d", back_fd, serv_fd);
    if (back_fd <= 0) {
        _LOG_E("connect back_fd:%d serv_fd:%d error", back_fd, serv_fd);
        goto _on_accept_error;
    }
    ssconn_t* front_conn = ssconn_init(serv_fd, back_fd, SSCONN_TYPE_SERV, PCONN_ST_WAIT, sslocal->net);
    if (!front_conn) {
        _LOG_E("ssconn_init front_conn error");
        goto _on_accept_error;
    }

    ssconn_t* back_conn = ssconn_init(back_fd, serv_fd, SSCONN_TYPE_CLI, PCONN_ST_WAIT, sslocal->net);
    if (!back_conn) {
        _LOG_E("ssconn_init back_conn error");
        goto _on_accept_error;
    }

    /* TODO: */
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
    if (!front_conn) {
        _LOG_E("ssconn_get front_conn error");
        return _ERR;
    }
    front_conn->status = PCONN_ST_ON;
    back_conn->status = PCONN_ST_ON;

    /* TODO: */
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
        _LOG_E("back_conn type error");
        return _ERR;
    }

    int rt = on_connected(sslocal, back_conn);
    /* TODO: */
    return rt;
}

//  ---------- callback end -----------

sslocal_t* sslocal_init(ssev_loop_t* loop, ssconfig_t* config) {
    sslocal_t* sslocal = calloc(1, sizeof(sslocal_t));
    if (sslocal == NULL) {
        return NULL;
    }
    /* TODO: */
    return sslocal;
}

void sslocal_free(sslocal_t* sslocal) {
    /* TODO: */
    return;
}
