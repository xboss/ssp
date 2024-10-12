#include "nwpipe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>

#include "ilist.h"
#include "network.h"
#include "stream_buf.h"
#include "uthash.h"

#ifdef DEBUG
#include "debug.h"
#endif

#ifndef _LOG
#define _LOG(fmt, ...)
#endif

#define _OK 0
#define _ERR -1

#define DEF_CONNECT_TIMEOUT (1000u * 5u)

struct nwpipe_s {
    network_t *nw;
    ssev_loop_t *loop;
    int server_fd;
    ilist_t *waiting_list;
    pipe_recv_cb_t on_pipe_recv;
    pipe_accept_cb_t on_pipe_accept;
};

/* --------------------- */

static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

/* ---------- protocol ----------- */
#define PACKET_HEAD_LEN 4

static int pack(int payload_len, const char *payload, char **buf) {
    if (payload_len <= 0 || !payload) {
        return 0;
    }
    *buf = (char *)malloc(payload_len + PACKET_HEAD_LEN);
    if (!*buf) {
        perror("allocate memory error");
        return -1;
    }
    int n_payload_len = htonl(payload_len);
    memcpy(*buf, &n_payload_len, PACKET_HEAD_LEN);
    memcpy(*buf + PACKET_HEAD_LEN, payload, payload_len);
    return payload_len + PACKET_HEAD_LEN;
}

static int unpack(nwpipe_t *pipe, int fd, const char *buf, int len) {
    /*     conn_t *conn = get_conn(pipe, fd);
        if (!conn) return _ERR; */
    _LOG("uppack fd:%d len:%d", fd, len);
    const char *pending_buf = buf;
    const char *p = buf;
    int payload_len = 0;
    int rlen = len;
    stream_buf_t *rcv_buf = pconn_get_rcv_buf(fd);
    while (rlen > 0) {
        if (rlen < PACKET_HEAD_LEN) {
            assert(pending_buf);
            assert(rlen > 0);
            if (sb_write(rcv_buf, pending_buf, rlen) != 0) {
                _LOG("unpack sb_write error 1");
                return _ERR;
            }
            break;
        }
        payload_len = ntohl(*(uint32_t *)(p));
        /* TODO: check payload_len */
        if (payload_len <= 0 || payload_len > 65535) {
            fprintf(stderr, "error payload_len:%d buf_len:%d rlen:%d fd:%d\n", payload_len, len, rlen, fd);
            return _ERR;
        }
        p += PACKET_HEAD_LEN;
        if (rlen < payload_len + PACKET_HEAD_LEN) {
            assert(pending_buf);
            assert(rlen > 0);
            if (sb_write(rcv_buf, pending_buf, rlen) != 0) {
                _LOG("unpack sb_write error 2");
                return _ERR;
            }
            break;
        }
        /* assert(conn); */
        /* assert(conn->fd > 0); */
        assert(p >= buf && p < buf + len);
        assert(p + payload_len <= buf + len);
        if (pipe->on_pipe_recv) pipe->on_pipe_recv(pipe, fd, p, payload_len);
        p += payload_len;
        pending_buf = p;
        rlen = len - (p - buf);
        if (pconn_get_status(fd) <= PCONN_ST_OFF) {
            return _ERR;
        }
    }
    _LOG("uppack fd:%d len:%d ok.", fd, len);
    return _OK;
}

/* --------------------- */

static int flush_tcp_send(network_t *nw, int fd) {
    _LOG("flush_tcp_send fd:%d status:%d", fd, pconn_get_status(fd));
    if (pconn_get_status(fd) < PCONN_ST_ON) return _OK;

    _LOG("flush_tcp_send in. fd:%d", fd);
    stream_buf_t *snd_buf = pconn_get_snd_buf(fd);
    int buf_len = sb_get_size(snd_buf);
    if (buf_len <= 0) {
        _LOG("flush_tcp_send no buf fd:%d", fd);
        return _OK;
    }
    char *buf = (char *)malloc(buf_len);
    if (!buf) {
        perror("allocate memory error");
        return _ERR;
    }
    if (sb_read_all(snd_buf, buf, buf_len) != buf_len) {
        _LOG("flush_tcp_send sb_read_all error");
        free(buf);
        return _ERR;
    }
    int rt = nw_tcp_send(nw, fd, buf, buf_len);
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

static int on_recv(network_t *nw, int fd, const char *buf, int len) {
    _LOG("nwpipe on_recv fd:%d len:%d", fd, len);
    /* if (pconn_get_status(fd) <= PCONN_ST_OFF) {
        _LOG("connection does not exists. fd:%d", fd);
        return _ERR;
    } */
    if (pconn_get_status(fd) < PCONN_ST_ON) {
        _LOG("on_recv conn status not ON. fd:%d st:%d type:%d", fd, pconn_get_status(fd), pconn_get_type(fd));
        return _ERR;
    }
    int rt = _OK;
    char *r_buf = (char *)buf;
    int r_buf_len = len;
    stream_buf_t *rcv_buf = pconn_get_rcv_buf(fd);
    int rcv_buf_sz = sb_get_size(rcv_buf);
    if (rcv_buf_sz > 0) {
        _LOG("nwpipe on_recv consume receiving buf fd:%d size:%d", fd, rcv_buf_sz);
        r_buf_len = rcv_buf_sz + len;
        r_buf = (char *)malloc(r_buf_len);
        if (!r_buf) {
            perror("allocate memory error");
            return _ERR;
        }
        if (sb_read_all(rcv_buf, r_buf, r_buf_len) != rcv_buf_sz) {
            _LOG("on_recv sb_read_all error");
            free(r_buf);
            return _ERR;
        }
        memcpy(r_buf + rcv_buf_sz, buf, len);
    }
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw);
    if (pconn_is_packet(fd)) {
        /* unpack */
        rt = unpack(pipe, fd, r_buf, r_buf_len);
    } else {
        if (pipe->on_pipe_recv) pipe->on_pipe_recv(pipe, fd, r_buf, r_buf_len);
    }
    if (r_buf != buf) free(r_buf);
    return rt;
}

static int on_close(network_t *nw, int fd) {
    _LOG("on close fd:%d", fd);
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw);
    nwpipe_close_conn(pipe, fd);
    /* pconn_set_status(fd, PCONN_ST_OFF);
    int cp_id = pconn_get_couple_id(fd);
    if (cp_id > 0) {
        _LOG("on close cp_fd:%d", cp_id);
        pconn_set_status(cp_id, PCONN_ST_OFF);
        nw_tcp_close(nw, cp_id);
    }
    pconn_free(fd, cp_id); */
    return _OK;
}

static int on_accept(network_t *nw, int fd) {
    _LOG("on_accept fd:%d", fd);
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw);
    /* assert(ilist_exist(pipe->waiting_list, fd) != 0); */
    int rt = pconn_init(fd, PCONN_TYPE_FR, mstime());
    if (rt != 0) return _ERR;
    rt = pconn_set_status(fd, PCONN_ST_WAIT);
    assert(rt == 0);
    rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    if (pipe->on_pipe_accept) pipe->on_pipe_accept(pipe, fd);
    return _OK;
}

static int on_connected(network_t *nw, int fd) {
    _LOG("on_connected fd:%d", fd);
    assert(pconn_get_type(fd) == PCONN_TYPE_BK);
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw);
    int cp_fd = pconn_get_couple_id(fd);
    if (pconn_get_status(cp_fd) <= PCONN_ST_OFF) {
        nwpipe_close_conn(pipe, fd);
        return _ERR;
    }
    assert(pconn_get_type(cp_fd) == PCONN_TYPE_FR);
    assert(pconn_get_status(cp_fd) == PCONN_ST_WAIT);
    int rt = pconn_set_status(cp_fd, PCONN_ST_ON);
    assert(rt == 0);
    rt = pconn_set_status(fd, PCONN_ST_ON);
    assert(rt == 0);
    rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    if (flush_tcp_send(nw, fd) != _OK) {
        nwpipe_close_conn(pipe, fd);
        return _ERR;
    }
    _LOG("on_connected ok. fd:%d", fd);
    return _OK;
}

static int on_writable(network_t *nw, int fd) {
    _LOG("on_writable fd:%d", fd);
    assert(pconn_get_type(fd) != 0);

    if (pconn_get_status(fd) == PCONN_ST_READY) {
        return on_connected(nw, fd);
    }
    int rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    return flush_tcp_send(nw, fd);
}

static int update(ssev_loop_t *loop, void *ud) {
    /* _LOG("update..."); */
    network_t *nw = (network_t *)ud;
    assert(nw);
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw);
    assert(pipe);

    if (pipe->waiting_list) {
        uint64_t ctime, now = mstime();
        int rt, id, i, sz = ilist_size(pipe->waiting_list);
        for (i = 0; i < sz; i++) {
            rt = ilist_pop(pipe->waiting_list, &id);
            if (rt == 0) {
                _LOG("update conn fd:%d type:%d size:%d", id, pconn_get_type(id), sz);
                if (pconn_get_status(id) != PCONN_ST_WAIT) continue;
                assert(pconn_get_type(id) == PCONN_TYPE_FR);
                ctime = pconn_get_ctime(id);
                assert(ctime > 0);
                if (now - ctime > DEF_CONNECT_TIMEOUT) {
                    pconn_free(id);
                    nw_tcp_close(nw, id);
                    _LOG("update close conn fd:%d size:%d", id, sz);
                } else {
                    break;
                }
            }
        }
    }

    return 0;
}

/* ---------- api ----------- */

nwpipe_t *nwpipe_init(ssev_loop_t *loop, int read_buf_size, const char *listen_ip, unsigned short listen_port,
                      pipe_recv_cb_t on_pipe_recv, pipe_accept_cb_t on_pipe_accept) {
    if (!listen_ip || listen_port <= 0) return NULL;
    nwpipe_t *pipe = (nwpipe_t *)malloc(sizeof(nwpipe_t));
    if (!pipe) {
        perror("allocate memory error");
        return NULL;
    }
    memset(pipe, 0, sizeof(nwpipe_t));
    pipe->nw = nw_init(loop, read_buf_size);
    if (!pipe->nw) {
        free(pipe);
        return NULL;
    }
    nw_set_userdata(pipe->nw, pipe);
    nw_set_recv_cb(pipe->nw, on_recv);
    nw_set_close_cb(pipe->nw, on_close);
    nw_set_writable_cb(pipe->nw, on_writable);
    pipe->server_fd = nw_tcp_init_server(pipe->nw, listen_ip, listen_port, on_accept);
    if (pipe->server_fd <= 0) {
        nw_free(pipe->nw);
        free(pipe);
        return NULL;
    }
    pipe->loop = loop;
    pipe->on_pipe_recv = on_pipe_recv;
    pipe->on_pipe_accept = on_pipe_accept;
    pipe->waiting_list = ilist_init();
    assert(pipe->waiting_list);

    ssev_set_update_cb(loop, update);

    return pipe;
}
static void free_close_cb(int id, void *u) {
    network_t *nw = (network_t *)u;
    assert(nw);
    nw_tcp_close(nw, id);
}

void nwpipe_free(nwpipe_t *pipe) {
    if (!pipe) return;
    if (pipe->waiting_list) ilist_free(pipe->waiting_list);
    pconn_free_all(pipe->nw, free_close_cb);
    nw_free(pipe->nw);
    free(pipe);
    _LOG("nwpipe free ok.");
}

static void close_conn(nwpipe_t *pipe, int id) {
    if (id <= 0) return;
    int type = pconn_get_type(id);
    int st = pconn_get_status(id);
    if (st != PCONN_ST_WAIT) {
        _LOG("close fd:%d", id);
        nw_tcp_close(pipe->nw, id);
    } else {
        assert(type == PCONN_TYPE_FR);
        if (type == PCONN_TYPE_FR) ilist_push(pipe->waiting_list, id);
    }
    pconn_set_status(id, PCONN_ST_OFF);
    if (st != PCONN_ST_WAIT) pconn_free(id);
}

void nwpipe_close_conn(nwpipe_t *pipe, int id) {
    if (!pipe || id <= 0) return;
    /* int st = pconn_get_status(id); */
    int cp_id = pconn_get_couple_id(id);
    close_conn(pipe, id);
    close_conn(pipe, cp_id);

    /* int cp_st = 0;
    if (cp_id > 0) cp_st = pconn_get_status(cp_id); */

    /* if (st != PCONN_ST_WAIT) {
        _LOG("close fd:%d", id);
        nw_tcp_close(pipe->nw, id);
    }

    pconn_set_status(id, PCONN_ST_OFF);
    if (cp_id > 0) pconn_set_status(cp_id, PCONN_ST_OFF);

    if (cp_id > 0) {
        _LOG("close cp fd:%d", cp_id);
        nw_tcp_close(pipe->nw, cp_id);
    }
    pconn_free(id, cp_id); */
    _LOG("nwpipe_close_conn fd:%d cp_fd:%d ok.", id, cp_id);
}

int nwpipe_connect(nwpipe_t *pipe, const char *ip, unsigned short port, int cp_fd, int is_secret, int is_packet) {
    if (!pipe || port <= 0 || !ip || cp_fd <= 0) return _ERR;
    assert(pconn_get_type(cp_fd) == PCONN_TYPE_FR);
    assert(pconn_get_couple_id(cp_fd) == 0);
    int fd = nw_tcp_connect(pipe->nw, ip, port);
    _LOG("nwpipe_connect fd:%d cp_fd:%d", fd, cp_fd);
    if (fd <= 0) {
        _LOG("tcp connect error");
        return _ERR;
    }
    /* assert(ilist_exist(pipe->waiting_list, fd) != 0); */
    int rt;
    rt = pconn_init(fd, PCONN_TYPE_BK, mstime());
    assert(rt == 0);
    /* rt = pconn_set_status(cp_fd, PCONN_ST_WAIT);
    assert(rt == 0); */
    rt = pconn_set_status(fd, PCONN_ST_READY);
    assert(rt == 0);
    rt = pconn_set_is_packet(fd, is_packet);
    assert(rt == 0);
    rt = pconn_set_is_secret(fd, is_secret);
    assert(rt == 0);
    rt = pconn_set_couple_id(fd, cp_fd);
    assert(rt == 0);
    rt = pconn_set_couple_id(cp_fd, fd);
    assert(rt == 0);
    return fd;
}

int nwpipe_send(nwpipe_t *pipe, int fd, const char *buf, int len) {
    if (!pipe || fd <= 0 || !buf || len <= 0) return _ERR;
    if (pconn_get_status(fd) <= PCONN_ST_OFF) return _ERR;
    char *w_buf = (char *)buf;
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
        _LOG("nwpipe_send sb_write error fd:%d len:%d", fd, w_buf_len);
        return _ERR;
    }
    rt = _OK;
    ssev_notify_write(pipe->loop, fd);
    if (pconn_get_status(fd) >= PCONN_ST_ON && pconn_can_write(fd)) { /* TODO: */
        rt = flush_tcp_send(pipe->nw, fd);
    }
    _LOG("nwpipe_send buf fd:%d rt:%d", fd, rt);
    return rt;
}
