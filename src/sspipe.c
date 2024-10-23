#include "sspipe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>

#include "ilist.h"
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
    _ALLOC(*buf, char *, payload_len + PACKET_HEAD_LEN);
    memset(*buf, 0, payload_len + PACKET_HEAD_LEN);
    int n_payload_len = htonl(payload_len);
    memcpy(*buf, &n_payload_len, PACKET_HEAD_LEN);
    memcpy(*buf + PACKET_HEAD_LEN, payload, payload_len);
    return payload_len + PACKET_HEAD_LEN;
}

static int unpack(sspipe_t *pipe, int fd, const char *buf, int len) {
    _LOG("uppack fd:%d len:%d", fd, len);
    const char *pending_buf = buf;
    const char *p = buf;
    int payload_len = 0;
    int rlen = len;
    stream_buf_t *rcv_buf = pconn_get_rcv_buf(fd);
    assert(rcv_buf);
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
            _LOG_E("error payload_len:%d buf_len:%d rlen:%d fd:%d", payload_len, len, rlen, fd);
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

static int flush_tcp_send(ssnet_t *net, int fd) {
    _LOG("flush_tcp_send fd:%d status:%d", fd, pconn_get_status(fd));
    if (pconn_get_status(fd) < PCONN_ST_ON) return _OK;
    _LOG("flush_tcp_send in. fd:%d", fd);
    stream_buf_t *snd_buf = pconn_get_snd_buf(fd);
    int buf_len = sb_get_size(snd_buf);
    if (buf_len <= 0) {
        _LOG("flush_tcp_send no buf fd:%d", fd);
        return _OK;
    }
    char *_ALLOC(buf, char *, buf_len);
    memset(buf, 0, buf_len);
    if (!buf) {
        perror("allocate memory error");
        return _ERR;
    }
    if (sb_read_all(snd_buf, buf, buf_len) != buf_len) {
        _LOG("flush_tcp_send sb_read_all error");
        free(buf);
        return _ERR;
    }
    int rt = ssnet_tcp_send(net, fd, buf, buf_len);
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
        _LOG("sspipe on_recv consume receiving buf fd:%d size:%d", fd, rcv_buf_sz);
        r_buf_len = rcv_buf_sz + len;
        _ALLOC(r_buf, char *, r_buf_len);
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
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    if (pconn_is_packet(fd)) {
        /* unpack */
        rt = unpack(pipe, fd, r_buf, r_buf_len);
    } else {
        if (pipe->on_pipe_recv) pipe->on_pipe_recv(pipe, fd, r_buf, r_buf_len);
    }
    if (r_buf != buf) free(r_buf);
    return rt;
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
    int rt = pconn_init(fd, PCONN_TYPE_FR, mstime());
    if (rt != 0) return _ERR;
    rt = pconn_set_status(fd, PCONN_ST_WAIT);
    assert(rt == 0);
    rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    if (pipe->on_pipe_accept) pipe->on_pipe_accept(pipe, fd);
    return _OK;
}

static int on_connected(ssnet_t *net, int fd) {
    _LOG("on_connected fd:%d", fd);
    assert(pconn_get_type(fd) == PCONN_TYPE_BK);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    int cp_fd = pconn_get_couple_id(fd);
    if (pconn_get_status(cp_fd) <= PCONN_ST_OFF) {
        sspipe_close_conn(pipe, fd);
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
    if (flush_tcp_send(net, fd) != _OK) {
        sspipe_close_conn(pipe, fd);
        return _ERR;
    }
    _LOG("on_connected ok. fd:%d", fd);
    return _OK;
}

static int on_writable(ssnet_t *net, int fd) {
    _LOG("on_writable fd:%d", fd);
    assert(pconn_get_type(fd) != 0);

    if (pconn_get_status(fd) == PCONN_ST_READY) {
        return on_connected(net, fd);
    }
    int rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    return flush_tcp_send(net, fd);
}

static int update(ssev_loop_t *loop, void *ud) {
    /* _LOG("update..."); */
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
}

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
    pipe->waiting_list = ilist_init();
    assert(pipe->waiting_list);
    ssev_set_update_cb(loop, update);
    return pipe;
}

void sspipe_free(sspipe_t *pipe) {
    if (!pipe) return;
    if (pipe->waiting_list) ilist_free(pipe->waiting_list);
    pconn_free_all(pipe->net, free_close_cb);
    ssnet_free(pipe->net);
    free(pipe);
    _LOG("sspipe free ok.");
}

static void close_conn(sspipe_t *pipe, int id) {
    if (id <= 0) return;
    int type = pconn_get_type(id);
    int st = pconn_get_status(id);
    if (st != PCONN_ST_WAIT) {
        _LOG("close fd:%d", id);
        ssnet_tcp_close(pipe->net, id);
    } else {
        assert(type == PCONN_TYPE_FR);
        if (type == PCONN_TYPE_FR) ilist_push(pipe->waiting_list, id);
    }
    pconn_set_status(id, PCONN_ST_OFF);
    if (st != PCONN_ST_WAIT) pconn_free(id);
}

void sspipe_close_conn(sspipe_t *pipe, int id) {
    if (!pipe || id <= 0) return;
    int cp_id = pconn_get_couple_id(id);
    close_conn(pipe, id);
    close_conn(pipe, cp_id);
    _LOG("sspipe_close_conn fd:%d cp_fd:%d ok.", id, cp_id);
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
    rt = pconn_init(fd, PCONN_TYPE_BK, mstime());
    assert(rt == 0);
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

int sspipe_send(sspipe_t *pipe, int fd, const char *buf, int len) {
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
        _LOG("sspipe_send sb_write error fd:%d len:%d", fd, w_buf_len);
        return _ERR;
    }
    rt = _OK;
    ssev_notify_write(pipe->loop, fd);
    if (pconn_get_status(fd) >= PCONN_ST_ON && pconn_can_write(fd)) {
        rt = flush_tcp_send(pipe->net, fd);
    }
    _LOG("sspipe_send buf fd:%d rt:%d", fd, rt);
    return rt;
}
