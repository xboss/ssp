#include "sspipe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

/* #include "ilist.h" */
#include "sslog.h"
#include "ssnet.h"
#include "stream_buf.h"
#include "uthash.h"

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

#define DEF_CONNECT_TIMEOUT (1000u * 5u)

struct sspipe_s {
    ssnet_t *net;
    ssev_loop_t *loop;
    int server_fd;
    /* ilist_t *waiting_list; */
    pipe_recv_cb_t on_pipe_recv;
    pipe_accept_cb_t on_pipe_accept;
};

/* --------------------- */

static int flush_tcp_send(ssnet_t *net, int fd) {
    _LOG("flush_tcp_send fd:%d status:%d", fd, pconn_get_status(fd));
    assert(pconn_get_status(fd) >= PCONN_ST_ON);
    stream_buf_t *snd_buf = pconn_get_snd_buf(fd);
    int buf_len = sb_get_size(snd_buf);
    if (buf_len <= 0) {
        _LOG("flush_tcp_send no buf fd:%d", fd);
        return _OK;
    }
    char *_ALLOC(buf, char *, buf_len);
    memset(buf, 0, buf_len);
    int rt = sb_read_all(snd_buf, buf, buf_len);
    assert(rt == buf_len);
    rt = ssnet_tcp_send(net, fd, buf, buf_len);
    if (rt == 0 || rt == -2) {
        _LOG("flush_tcp_send error fd:%d rt:%d len:%d", fd, rt, buf_len);
        free(buf);
        return _ERR;
    } else if (rt == -1) {
        /* pending */
        pconn_set_can_write(fd, 0);
        _LOG("flush_tcp_send pending send fd:%d buf_len:%d", fd, buf_len);
        sb_write(snd_buf, buf, buf_len);
    } else if (rt < buf_len) {
        /* remain */
        _LOG("flush_tcp_send remain send fd:%d len:%d", fd, rt);
        assert(rt > 0);
        sb_write(snd_buf, buf + rt, buf_len - rt);
    }
    free(buf);
    _LOG("flush_tcp_send ok. fd:%d", fd);
    return _OK;
}

/* ---------- callback ----------- */

static int on_recv(ssnet_t *net, int fd, const char *buf, int len, struct sockaddr *addr) {
    _LOG("sspipe on_recv fd:%d len:%d", fd, len);
    pconn_type_t type = pconn_get_type(fd);
    assert(type == PCONN_TYPE_FR || type == PCONN_TYPE_BK);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    assert(pipe);
    pconn_st_t st = pconn_get_status(fd);
    if (st == PCONN_ST_OFF) {
        sspipe_close_conn(pipe, fd);
        return _OK;
    }
    int rt = pconn_rcv(fd, buf, len);
    assert(rt == 0);
    if (st == PCONN_ST_WAIT) {
        return _OK;
    }
    assert(rt == PCONN_ST_ON);

    stream_buf_t *rcv_buf = pconn_get_rcv_buf(fd);
    assert(rcv_buf != NULL);
    int tmp_len = sb_get_size(rcv_buf);
    char *_ALLOC(tmp_buf, char *, tmp_len);
    rt = sb_read_all(rcv_buf, tmp_buf, tmp_len);
    assert(rt == tmp_len);

    /* if unpack */
    if (!pconn_is_packet(fd)) {
        if (pipe->on_pipe_recv) rt = pipe->on_pipe_recv(pipe, fd, tmp_buf, tmp_len);
        /* TODO: if send */
        free(tmp_buf);
        return rt;
    }

    char *p = tmp_buf;
    int l = tmp_len;
    char *plain = NULL;
    int plain_len = 0;
    char *cihper = NULL;
    int cipher_len = 0;
    while (p < tmp_buf + tmp_len) {
        p = unpack(p, l);
        plain = ;
        plain_len = ;
        if (pconn_is_secret(fd)) {
            plain = aes_decrypt(g_conf.key, buf, len, &plain_len);
            _LOG("decrypt ");
        }
        if (pipe->on_pipe_recv) rt = pipe->on_pipe_recv(pipe, fd, plain, plain_len);
        if (rt == _OK) {
            cihper = ;
            cihper_len = ;
            if (pconn_is_secret(fd)) {
                cihper = aes_encrypt(g_conf.key, plain, plain_len, &cipher_len);
                _LOG("encrypt ");
                assert(cipher_len % 16 == 0);
            }
            /* TODO: send */
        }
    }
    free(tmp_buf);
    /* if decrypt */

    /* if send */
    /* if encrypt */
    /* if pack */
    return _OK;
}

static int on_close(ssnet_t *net, int fd) {
    _LOG("on close fd:%d", fd);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    sspipe_close_conn(pipe, fd);
    return _OK;
}

static int on_accept(ssnet_t *net, int fd) {
    _LOG("on_accept fd:%d", fd);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    assert(pipe);
    int rt = pconn_init(fd, PCONN_TYPE_FR);
    if (rt != 0) return _ERR;
    rt = pconn_chg_status(fd, PCONN_ST_WAIT);
    assert(rt != PCONN_ST_NONE);
    rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    if (pipe->on_pipe_accept) pipe->on_pipe_accept(pipe, fd);
    return _OK;
}

static int on_connected(ssnet_t *net, int fd) {
    _LOG("on_connected fd:%d", fd);
    if (!pconn_is_exist(fd)) {
        _LOG("on_connected fd:%d does not exist, close", fd);
        ssnet_tcp_close(net, fd);
        return _OK;
    }
    if (pconn_get_status(fd) == PCONN_ST_OFF) {
        _LOG("on_connected fd:%d off or not exist, close and free", fd);
        ssnet_tcp_close(net, fd);
        pconn_free(fd);
        return _OK;
    }
    assert(pconn_get_type(fd) == PCONN_TYPE_BK);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    assert(pipe);

    /* TODO: debug */
    int cp_fd = pconn_get_couple_id(fd);
    assert(pconn_get_type(cp_fd) == PCONN_TYPE_FR);
    assert(pconn_get_status(cp_fd) == PCONN_ST_ON);

    int rt = pconn_chg_status(fd, PCONN_ST_ON);
    assert(rt != PCONN_ST_NONE);
    _LOG("on_connected ok. fd:%d", fd);
    return _OK;
}

static int on_writable(ssnet_t *net, int fd) {
    _LOG("on_writable fd:%d", fd);
    assert(pconn_get_type(fd) != 0);
    int rt = _OK;
    if (pconn_get_status(fd) == PCONN_ST_READY) {
        rt = on_connected(net, fd);
    }
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    assert(pipe);
    if (rt == _OK) {
        rt = pconn_set_can_write(fd, 1);
        assert(rt == 0);
        rt = flush_tcp_send(net, fd);
        if (rt != _OK) {
            sspipe_close_conn(pipe, fd);
        }
    }
    return rt;
}

/* static int update(ssev_loop_t *loop, void *ud) {
    ssnet_t *net = (ssnet_t *)ud;
    assert(net);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    assert(pipe);

    if (pipe->waiting_list) {
        uint64_t ctime, now = mstime();
        int rt, id, i, sz = ilist_size(pipe->waiting_list);
        for (i = 0; i < sz; i++) {
            rt = ilist_pop(pipe->waiting_list, &id);
            if (rt != 0) break;
            _LOG("update conn fd:%d type:%d size:%d", id, pconn_get_type(id), sz);
            if (pconn_get_status(id) != PCONN_ST_WAIT) continue;
            assert(pconn_get_type(id) == PCONN_TYPE_FR);
            ctime = pconn_get_ctime(id);
            assert(ctime > 0);
            if (now - ctime > DEF_CONNECT_TIMEOUT) {
                pconn_free(id);
                ssnet_tcp_close(net, id);
                _LOG("update close conn fd:%d size:%d", id, sz);
            }
        }
    }
    return 0;
} */

static void free_close_cb(int id, void *u) {
    ssnet_t *net = (ssnet_t *)u;
    assert(net);
    ssnet_tcp_close(net, id);
}

/* ---------- api ----------- */

sspipe_t *sspipe_init(ssev_loop_t *loop, int read_buf_size, const char *listen_ip, unsigned short listen_port,
                      pipe_recv_cb_t on_pipe_recv, pipe_accept_cb_t on_pipe_accept) {
    if (!listen_ip || listen_port <= 0) return NULL;
    sspipe_t *_ALLOC(pipe, sspipe_t *, sizeof(sspipe_t));
    memset(pipe, 0, sizeof(sspipe_t));
    pipe->net = ssnet_init(loop, read_buf_size);
    if (!pipe->net) {
        free(pipe);
        return NULL;
    }
    ssnet_set_userdata(pipe->net, pipe);
    ssnet_set_recv_cb(pipe->net, on_recv);
    ssnet_set_close_cb(pipe->net, on_close);
    ssnet_set_writable_cb(pipe->net, on_writable);
    pipe->server_fd = ssnet_tcp_init_server(pipe->net, listen_ip, listen_port, on_accept);
    if (pipe->server_fd <= 0) {
        ssnet_free(pipe->net);
        free(pipe);
        return NULL;
    }
    pipe->loop = loop;
    pipe->on_pipe_recv = on_pipe_recv;
    pipe->on_pipe_accept = on_pipe_accept;
    /*     pipe->waiting_list = ilist_init();
        assert(pipe->waiting_list);
        ssev_set_update_cb(loop, update); */
    return pipe;
}

void sspipe_free(sspipe_t *pipe) {
    if (!pipe) return;
    /* if (pipe->waiting_list) ilist_free(pipe->waiting_list); */
    pconn_free_all(pipe->net, free_close_cb);
    ssnet_free(pipe->net);
    free(pipe);
    _LOG("sspipe free ok.");
}

/* static void close_conn(sspipe_t *pipe, int id) {
    if (id <= 0) return;
    int type = pconn_get_type(id);
    assert(type == PCONN_TYPE_FR || type == PCONN_TYPE_BK);
    if (type == PCONN_TYPE_BK) {
        _LOG("close fd:%d", id);
        ssnet_tcp_close(pipe->net, id);
        pconn_free(id);
    }
    if (type == PCONN_TYPE_FR) {
        int st = pconn_get_status(id);
        if (st != PCONN_ST_WAIT) {
            _LOG("close fd:%d", id);
            ssnet_tcp_close(pipe->net, id);
            pconn_free(id);
        } else {
            if (type == PCONN_TYPE_FR) ilist_push(pipe->waiting_list, id);
            int rt = ssev_unwatch(pipe->loop, SSEV_EV_ALL, id);
            assert(rt == 0);
            rt = pconn_chg_status(id, PCONN_ST_OFF);
            assert(rt != PCONN_ST_NONE);
        }
    }
} */

void sspipe_close_conn(sspipe_t *pipe, int fd) {
    if (!pipe || fd <= 0) return;
    if (!pconn_is_exist(fd)) return;
    int cp_fd = pconn_get_couple_id(fd);
    pconn_chg_status(fd, PCONN_ST_OFF);
    ssnet_tcp_close(pipe->net, fd);
    pconn_free(fd);
    _LOG("sspipe_close_conn fd:%d", fd);
    if (cp_fd > 0) {
        ssnet_tcp_close(pipe->net, cp_fd);
        pconn_free(cp_fd);
        _LOG("sspipe_close_conn cp_fd:%d", cp_fd);
    }
    _LOG("sspipe_close_conn fd:%d cp_fd:%d ok.", fd, cp_fd);
}

int sspipe_connect(sspipe_t *pipe, const char *ip, unsigned short port, int cp_fd, int is_secret, int is_packet) {
    if (!pipe || port <= 0 || !ip || cp_fd <= 0) return _ERR;
    assert(pconn_get_type(cp_fd) == PCONN_TYPE_FR);
    assert(pconn_get_couple_id(cp_fd) == 0);
    int fd = ssnet_tcp_connect(pipe->net, ip, port);
    _LOG("sspipe_connect fd:%d cp_fd:%d", fd, cp_fd);
    if (fd <= 0) {
        _LOG("tcp connect error");
        return _ERR;
    }
    int rt;
    rt = pconn_init(fd, PCONN_TYPE_BK);
    assert(rt == 0);
    rt = pconn_chg_status(fd, PCONN_ST_READY);
    assert(rt != PCONN_ST_NONE);
    rt = pconn_set_is_packet(fd, is_packet);
    assert(rt == 0);
    rt = pconn_set_is_secret(fd, is_secret);
    assert(rt == 0);
    rt = pconn_set_couple_id(fd, cp_fd);
    assert(rt == 0);
    rt = pconn_set_couple_id(cp_fd, fd);
    assert(rt == 0);
    rt = pconn_chg_status(cp_fd, PCONN_ST_ON);
    assert(rt != PCONN_ST_NONE);
    return fd;
}

int sspipe_send(sspipe_t *pipe, int fd, const char *buf, int len) {
    if (!pipe || fd <= 0 || !buf || len <= 0) return _ERR;
    if (pconn_get_status(fd) <= PCONN_ST_OFF) return _ERR;
    int rt = pconn_send(fd, buf, len);
    /*     char *w_buf = (char *)buf;
        int w_buf_len = len;
        if (pconn_is_packet(fd)) {
            w_buf_len = pack(len, buf, &w_buf);
            assert((w_buf_len - 4) % 16 == 0);
            assert((w_buf_len - 4) == len);
        }
        assert(w_buf);
        assert(w_buf_len > 0);
        int rt = sb_write(pconn_get_snd_buf(fd), w_buf, w_buf_len);
        if (w_buf != buf) free(w_buf);
        if (rt != 0) {
            _LOG("sspipe_send sb_write error fd:%d len:%d", fd, w_buf_len);
            return _ERR;
        }
        rt = _OK;
        ssev_notify_write(pipe->loop, fd);
        if (pconn_get_status(fd) >= PCONN_ST_ON && pconn_can_write(fd)) {
            rt = flush_tcp_send(pipe->net, fd);
        } */
    _LOG("sspipe_send buf fd:%d rt:%d", fd, rt);
    return rt;
}
