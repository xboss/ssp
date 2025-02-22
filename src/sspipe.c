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

// connection start

#define MAX_CLOSE_FD_ARR_SIZE 1024
static int g_close_fd_arr[MAX_CLOSE_FD_ARR_SIZE] = {0};
static int g_close_fd_arr_len = 0;
static ssconn_t* g_conn_tb = NULL;

static int real_close(int fd) {
    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG("ssconn_get conn error");
        return _ERR;
    }
    ssnet_t* net = conn->net;
    assert(net);
    conn->status = PCONN_ST_OFF;
    ssnet_tcp_close(net, fd);
    return _OK;
}

ssconn_t* ssconn_init(int fd, int cp_fd, ssconn_type_t type, ssconn_st_t status, ssnet_t* net){
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
        real_close(conn->fd);
        real_close(conn->cp_fd);
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
    if (!g_conn_tb) {
        return;
    }
    ssconn_t *conn, *tmp;
    HASH_ITER(hh, g_conn_tb, conn, tmp) {
        ssconn_free(conn);
    }
    g_conn_tb = NULL;
}

int ssconn_close(int fd) {
    ssconn_t* conn = ssconn_get(fd);
    if (!conn) {
        _LOG("ssconn_get conn error");
        return _ERR;
    }
    conn->status = PCONN_ST_OFF;
    int cp_fd = conn->cp_fd;
    ssconn_t* cp_conn = ssconn_get(cp_fd);
    if (!cp_conn) {
        _LOG("ssconn_get cp_conn error");
        return _ERR;
    }
    cp_conn->status = PCONN_ST_OFF;

    if (g_close_fd_arr_len >= MAX_CLOSE_FD_ARR_SIZE) {
        _LOG_E("close fd arr is full");
        real_close(g_close_fd_arr[0]);
        g_close_fd_arr[0] = fd;
        return _OK;
    }
    g_close_fd_arr[g_close_fd_arr_len++] = fd;
    return _OK;
}

int ssconn_close_all() {
    for (int i = 0; i < g_close_fd_arr_len; i++) {
        real_close(g_close_fd_arr[i]);
    }
    g_close_fd_arr_len = 0;
    return _OK;
}

// connection end