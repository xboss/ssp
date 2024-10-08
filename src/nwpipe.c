#include "nwpipe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>

#include "network.h"
#include "uthash.h"

#ifdef DEBUG
#include "debug.h"
#endif

#ifndef _LOG
#define _LOG(fmt, ...)
#endif

#define _OK 0
#define _ERR -1

#define _GET_CONN_FROM_NW                             \
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw); \
    conn_t *conn = get_conn(pipe, fd)

struct msg_s {
    char *buf;
    int buf_len;
    int offset;
    struct msg_s *next;
};
typedef struct msg_s msg_t;

struct msg_queue_s {
    int size;
    int sum_buf_len;
    msg_t *head;
    msg_t *tail;
};
typedef struct msg_queue_s msg_queue_t;

struct conn_s {
    int fd;
    int cp_fd;
    int is_secret;
    int is_packet;
    int status;
    int type;
    int ex;
    int can_write;
    msg_queue_t *sending_q;
    msg_queue_t *receiving_q;
    UT_hash_handle hh;
};
typedef struct conn_s conn_t;

struct nwpipe_s {
    network_t *nw;
    ssev_loop_t *loop;
    int server_fd;
    conn_t *conn_tb;
    pipe_recv_cb_t on_pipe_recv;
    pipe_accept_cb_t on_pipe_accept;
};

/* --------------------- */

/* static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
} */

static void free_msg(msg_t *m) {
    if (!m) {
        return;
    }
    if (m->buf) {
        free(m->buf);
    }
    m->buf_len = 0;
    free(m);
}

static msg_t *init_msg(const char *src_buf, int len) {
    if (len <= 0 || !src_buf) {
        return NULL;
    }
    msg_t *m = (msg_t *)malloc(sizeof(msg_t));
    if (!m) {
        perror("allocate memory error");
        return NULL;
    }
    m->offset = 0;
    m->buf_len = len;
    m->buf = (char *)malloc(len);
    if (!m->buf) {
        perror("allocate memory error");
        free_msg(m);
        return NULL;
    }
    memcpy(m->buf, src_buf, len);
    return m;
}

static msg_queue_t *init_msg_queue() {
    msg_queue_t *q = (msg_queue_t *)malloc(sizeof(msg_queue_t));
    if (!q) {
        perror("allocate memory error");
        return NULL;
    }
    memset(q, 0, sizeof(msg_queue_t));
    return q;
}

static void free_msg_queue(msg_queue_t *q) {
    if (!q) {
        return;
    }
    msg_t *m = NULL;
    while (q->size > 0 || q->head) {
        m = q->head;
        q->head = m->next;
        free_msg(m);
        q->size--;
        if (q->size == 0) {
            q->tail = NULL;
        }
    }
    q->sum_buf_len = 0;
    assert(q->size == 0); /* TODO: debug */
    free(q);
}

static int push_msg(msg_queue_t *q, msg_t *msg) {
    if (!q || !msg) {
        return -1;
    }
    if (q->size == 0) {
        q->head = msg;
    } else {
        q->tail->next = msg;
    }
    q->tail = msg;
    q->tail->next = NULL;
    q->size++;
    q->sum_buf_len += msg->buf_len;
    return 0;
}

static msg_t *pop_msg(msg_queue_t *q) {
    if (!q) {
        return NULL;
    }
    if (q->size == 0) {
        return NULL;
    }
    msg_t *m = q->head;
    q->head = m->next;
    q->size--;
    q->sum_buf_len -= m->buf_len;
    if (q->size == 0) {
        q->tail = NULL;
    }

    return m;
}

static msg_t *take_msg(msg_queue_t *q) {
    if (!q) {
        return NULL;
    }
    if (q->size == 0) {
        return NULL;
    }
    return q->head;
}

static conn_t *init_conn(int fd) {
    conn_t *c = (conn_t *)malloc(sizeof(conn_t));
    if (!c) {
        perror("allocate memory error");
        return NULL;
    }
    memset(c, 0, sizeof(conn_t));
    c->fd = fd;
    c->sending_q = init_msg_queue();
    if (!c->sending_q) {
        free(c);
        return NULL;
    }
    c->receiving_q = init_msg_queue();
    if (!c->receiving_q) {
        free_msg_queue(c->sending_q);
        free(c);
        return NULL;
    }
    c->can_write = 0;
    return c;
}

static int conn_tb_size(nwpipe_t *pipe) {
    if (!pipe || !pipe->conn_tb) {
        return 0;
    }
    return HASH_COUNT(pipe->conn_tb);
}

static conn_t *get_conn(nwpipe_t *pipe, int fd) {
    if (!pipe || !pipe->conn_tb || fd <= 0) {
        return NULL;
    }
    conn_t *c = NULL;
    HASH_FIND_INT(pipe->conn_tb, &fd, c);
    return c;
}

static int add_conn(nwpipe_t *pipe, conn_t *c) {
    if (!c) {
        return -1;
    }
    HASH_ADD_INT(pipe->conn_tb, fd, c);
    return 0;
}

static void del_conn(nwpipe_t *pipe, conn_t *c) {
    if (!pipe || !c) {
        return;
    }
    _LOG("del conn fd:%d", c->fd);
    free_msg_queue(c->sending_q);
    c->sending_q = NULL;
    free_msg_queue(c->receiving_q);
    c->receiving_q = NULL;
    if (pipe->conn_tb) {
        HASH_DEL(pipe->conn_tb, c);
    }
    memset(c, 0, sizeof(conn_t)); /* TODO: debug to del*/
    free(c);
}

static void free_conn_table(nwpipe_t *pipe) {
    if (!pipe || !pipe->conn_tb) {
        return;
    }
    conn_t *c, *tmp;
    HASH_ITER(hh, pipe->conn_tb, c, tmp) { del_conn(pipe, c); }
    pipe->conn_tb = NULL;
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
    conn_t *conn = get_conn(pipe, fd);
    if (!conn) return _ERR;
    _LOG("uppack fd:%d len:%d", fd, len);
    const char *pending_buf = buf;
    const char *p = buf;
    int payload_len = 0;
    int rlen = len;
    msg_t *m = NULL;
    while (rlen > 0) {
        if (rlen < PACKET_HEAD_LEN) {
            assert(pending_buf);
            assert(rlen > 0);
            m = init_msg(pending_buf, rlen);
            assert(m);
            assert(conn);
            assert(conn->fd > 0);
            assert(conn->receiving_q);
            if (push_msg(conn->receiving_q, m) != 0) {
                _LOG("unpack push_msg error");
                free_msg(m);
                return _ERR;
            }
            break;
        }
        payload_len = ntohl(*(uint32_t *)(p));
        /* TODO: check payload_len */
        if (payload_len <= 0 || payload_len > 65535) {
            fprintf(stderr, "error payload_len:%d buf_len:%d rlen:%d fd:%d type:%d\n", payload_len, len, rlen, fd,
                    conn->type);
            return _ERR;
        }
        p += PACKET_HEAD_LEN;
        if (rlen < payload_len + PACKET_HEAD_LEN) {
            assert(pending_buf);
            assert(rlen > 0);
            m = init_msg(pending_buf, rlen);
            assert(m);
            assert(conn);
            assert(conn->fd > 0);
            assert(conn->receiving_q);
            if (push_msg(conn->receiving_q, m) != 0) {
                _LOG("unpack push_msg error");
                free_msg(m);
                return _ERR;
            }
            break;
        }
        assert(conn);
        assert(conn->fd > 0);
        assert(p >= buf && p < buf + len);
        assert(p + payload_len <= buf + len);
        if (pipe->on_pipe_recv) pipe->on_pipe_recv(pipe, conn->fd, p, payload_len);
        p += payload_len;
        pending_buf = p;
        rlen = len - (p - buf);
        conn = get_conn(pipe, fd);
        if (!conn) return _ERR;
    }
    _LOG("uppack fd:%d len:%d ok.", fd, len);
    return _OK;
}

/* --------------------- */

static int flush_tcp_send(network_t *nw, conn_t *c) {
    assert(c);
    _LOG("flush_tcp_send fd:%d", c->fd);

    if (c->status != NWPIPE_CONN_ST_ON) {
        _LOG("flush_tcp_send conn status error. fd:%d st:%d", c->fd, c->status);
        return _OK;
    }

    /* consume sending buf */
    _LOG("flush_tcp_send in. fd:%d", c->fd);
    msg_t *m = NULL;
    int rt;
    char *buf;
    int buf_len;
    while (c->sending_q->size > 0) {
        m = take_msg(c->sending_q);
        if (!m) continue;
        buf = m->buf + m->offset;
        buf_len = m->buf_len - m->offset;
        if (buf_len <= 0) {
            _LOG("flush_tcp_send offset error buf_len:%d offset:%d", m->buf_len, m->offset);
            m = pop_msg(c->sending_q);
            free_msg(m);
            continue;
        }
        assert(buf >= m->buf);
        assert(m->offset >= 0);
        rt = nw_tcp_send(nw, c->fd, buf, buf_len);
        if (rt == 0 || rt == -2) {
            _LOG("flush_tcp_send error fd:%d rt:%d len:%d", c->fd, rt, buf_len);
            return _ERR;
        } else if (rt == -1) {
            /* pending */
            c->can_write = 0;
            _LOG("flush_tcp_send pending send fd:%d type:%d snd_buf_len:%d snd_q_size:%d", c->fd, c->type,
                 c->sending_q->sum_buf_len, c->sending_q->size);
            break;
        } else if (rt < buf_len) {
            /* remain */
            assert(rt > 0);
            m->offset += rt;
            _LOG("flush_tcp_send remain send fd:%d len:%d", c->fd, rt);
        } else {
            /* ok */
            assert(rt == buf_len);
            m = pop_msg(c->sending_q);
            free_msg(m);

            /* TODO: debug */
            /*             int snd_q_size = 0;
                        int snd_buf_len = 0;
                        if (c->sending_q) {
                            snd_q_size = c->sending_q->size;
                            snd_buf_len = c->sending_q->sum_buf_len;
                        }
                        _LOG("flush_tcp_send real send ok. fd:%d len:%d type:%d snd_buf_len:%d snd_q_size:%d", c->fd,
               rt, c->type, snd_buf_len, snd_q_size); */
        }
    }
    _LOG("flush_tcp_send ok. fd:%d", c->fd);
    return _OK;
}

/* ---------- callback ----------- */

static int on_recv(network_t *nw, int fd, const char *buf, int len) {
    _LOG("nwpipe on_recv fd:%d len:%d", fd, len);
    _GET_CONN_FROM_NW;
    if (!conn) {
        _LOG("connection does not exists. fd:%d", fd);
        return _ERR;
    }
    int rt = _OK;
    char *r_buf = (char *)buf;
    int r_buf_len = 0;
    if (conn->receiving_q && conn->receiving_q->size > 0) {
        /* consume pending buf */
        _LOG("nwpipe on_recv consume pending buf fd:%d size:%d sum_buf_len:%d", fd, conn->receiving_q->size,
             conn->receiving_q->sum_buf_len);
        assert(conn->receiving_q->sum_buf_len > 0);
        r_buf = (char *)malloc(conn->receiving_q->sum_buf_len + len);
        if (!r_buf) {
            perror("allocate memory error");
            return _ERR;
        }
        int i;
        msg_t *m;
        for (i = 0; i < conn->receiving_q->size; i++) {
            m = pop_msg(conn->receiving_q);
            if (m) {
                memcpy(r_buf + r_buf_len, m->buf, m->buf_len);
                r_buf_len += m->buf_len;
                free_msg(m);
            }
        }
        memcpy(r_buf + r_buf_len, buf, len);
        r_buf_len += len;
        _LOG("nwpipe on_recv consume pending buf ok. fd:%d size:%d sum_buf_len:%d", fd, conn->receiving_q->size,
             conn->receiving_q->sum_buf_len);
    } else {
        r_buf_len = len;
    }

    if (conn->is_packet) {
        /* unpack */
        rt = unpack(pipe, fd, r_buf, r_buf_len);
    } else {
        if (pipe->on_pipe_recv) pipe->on_pipe_recv(pipe, conn->fd, r_buf, r_buf_len);
    }
    if (r_buf != buf) free(r_buf);
    return rt;
}

static int on_close(network_t *nw, int fd) {
    _LOG("on close fd:%d", fd);
    _GET_CONN_FROM_NW;
    if (conn) {
        conn->status = NWPIPE_CONN_ST_OFF;
        conn_t *cp = get_conn(pipe, conn->cp_fd);
        if (cp) {
            cp->status = NWPIPE_CONN_ST_OFF;
            nw_tcp_close(pipe->nw, cp->fd);
            del_conn(pipe, cp);
        }
        del_conn(pipe, conn);
    }
    return _OK;
}

static int on_accept(network_t *nw, int fd) {
    _LOG("on_accept fd:%d", fd);
    _GET_CONN_FROM_NW;
    assert(!conn);
    conn = init_conn(fd);
    if (!conn) return _ERR;
    add_conn(pipe, conn);
    conn->type = NWPIPE_CONN_TYPE_FR;
    conn->status = NWPIPE_CONN_ST_ON;
    conn->can_write = 1;
    if (pipe->on_pipe_accept) pipe->on_pipe_accept(pipe, fd);
    return _OK;
}

static int on_connected(network_t *nw, int fd) {
    _LOG("on_connected fd:%d", fd);
    _GET_CONN_FROM_NW;
    if (!conn) return _ERR;
    conn->status = NWPIPE_CONN_ST_ON;
    conn->can_write = 1;
    if (flush_tcp_send(nw, conn) != _OK) {
        nwpipe_close_conn(pipe, fd);
        return _ERR;
    }
    _LOG("on_connected ok. fd:%d", fd);
    return _OK;
}

static int on_writable(network_t *nw, int fd) {
    _LOG("on_writable fd:%d", fd);
    _GET_CONN_FROM_NW;
    if (!conn) {
        _LOG("on_writable conn does not exists. fd:%d", fd);
        return _ERR;
    }
    if (conn->status == NWPIPE_CONN_ST_READY) {
        return on_connected(nw, fd);
    }
    conn->can_write = 1;
    return flush_tcp_send(nw, conn);
}

/* TODO: debug */
/* static int update(ssev_loop_t *loop, void *ud) {
    _LOG("update...");
    network_t *nw = (network_t *)ud;
    assert(nw);
    nwpipe_t *pipe = (nwpipe_t *)nw_get_userdata(nw);
    assert(pipe);
    if (pipe->conn_tb) {
        conn_t *c, *tmp;
        HASH_ITER(hh, pipe->conn_tb, c, tmp) {
            int rcv_q_len = 0;
            int rcv_buf_len = 0;
            if (c->receiving_q) {
                rcv_q_len = c->receiving_q->size;
                rcv_buf_len = c->receiving_q->sum_buf_len;
            }
            int snd_q_len = 0;
            int snd_buf_len = 0;
            if (c->sending_q) {
                snd_q_len = c->sending_q->size;
                snd_buf_len = c->sending_q->sum_buf_len;
            }

            _LOG("___ stat ___ fd:%d rcv_q_len:%d rcv_buf_len:%d snd_q_len:%d snd_buf_len:%d type:%d, status:%d", c->fd,
                 rcv_q_len, rcv_buf_len, snd_q_len, snd_buf_len, c->type, c->status);
        }
    }
    return 0;
} */

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
    pipe->conn_tb = NULL;
    pipe->loop = loop;
    pipe->on_pipe_recv = on_pipe_recv;
    pipe->on_pipe_accept = on_pipe_accept;

    /* TODO: */
    /* ssev_set_update_cb(loop, update); */

    return pipe;
}

void nwpipe_free(nwpipe_t *pipe) {
    if (!pipe) return;
    if (pipe->nw) nw_free(pipe->nw);
    free_conn_table(pipe);
    free(pipe);
    _LOG("nwpipe free ok.");
}

void nwpipe_close_conn(nwpipe_t *pipe, int fd) {
    conn_t *c = get_conn(pipe, fd);
    if (!c) return;
    c->status = NWPIPE_CONN_ST_OFF;
    conn_t *cp = get_conn(pipe, c->cp_fd);
    _LOG("close fd:%d", c->fd);
    nw_tcp_close(pipe->nw, c->fd);
    del_conn(pipe, c);

    if (!cp) return;
    cp->status = NWPIPE_CONN_ST_OFF;
    _LOG("close cp fd:%d", cp->fd);
    nw_tcp_close(pipe->nw, cp->fd);
    del_conn(pipe, cp);
}

int nwpipe_connect(nwpipe_t *pipe, const char *ip, unsigned short port, int cp_fd, int is_secret, int is_packet) {
    if (!pipe || port <= 0 || !ip || cp_fd <= 0) return _ERR;
    conn_t *conn = init_conn(0);
    if (!conn) return _ERR;
    conn->status = NWPIPE_CONN_ST_READY;
    conn->type = NWPIPE_CONN_TYPE_BK;
    conn->is_packet = is_packet;
    conn->is_secret = is_secret;
    int fd = nw_tcp_connect(pipe->nw, ip, port);
    _LOG("nwpipe_connect fd:%d cp_fd:%d", fd, cp_fd);
    if (fd <= 0) {
        _LOG("tcp connect error");
        del_conn(pipe, conn);
        return _ERR;
    }
    conn->fd = fd;
    conn_t *cp_conn = get_conn(pipe, cp_fd);
    if (!cp_conn) {
        nwpipe_close_conn(pipe, fd);
        return _ERR;
    }
    add_conn(pipe, conn);
    conn->cp_fd = cp_fd;
    cp_conn->cp_fd = fd;
    return fd;
}

int nwpipe_send(nwpipe_t *pipe, int fd, const char *buf, int len) {
    if (!pipe || fd <= 0 || !buf || len <= 0) return _ERR;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return _ERR;
    char *w_buf = (char *)buf;
    int w_buf_len = len;
    if (c->is_packet) {
        w_buf_len = pack(len, buf, &w_buf);
        assert((w_buf_len - 4) % 16 == 0);
        assert((w_buf_len - 4) == len);
    }
    assert(w_buf);
    assert(w_buf_len > 0);
    msg_t *m = init_msg(w_buf, w_buf_len);
    if (w_buf && w_buf != buf) free(w_buf);
    if (!m) {
        _LOG("nwpipe_send init_msg error fd:%d len:%d", c->fd, w_buf_len);
        return _ERR;
    }
    push_msg(c->sending_q, m);
    int rt = _OK;
    ssev_notify_write(pipe->loop, fd);
    if (c->status == NWPIPE_CONN_ST_ON && c->can_write) {
        rt = flush_tcp_send(pipe->nw, c);
    }
    _LOG("nwpipe_send buf fd:%d rt:%d can_write:%d", c->fd, rt, c->can_write);
    return rt;
}

int nwpipe_get_couple_fd(nwpipe_t *pipe, int fd) {
    if (!pipe || fd <= 0) return 0;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return 0;
    return c->cp_fd;
}

int nwpipe_is_conn_secret(nwpipe_t *pipe, int fd) {
    if (!pipe || fd <= 0) return 0;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return 0;
    return c->is_secret;
}

void nwpipe_set_conn_secret(nwpipe_t *pipe, int fd, int is_secret) {
    if (!pipe || fd <= 0) return;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return;
    c->is_secret = is_secret;
}

void nwpipe_set_conn_packet(nwpipe_t *pipe, int fd, int is_packet) {
    if (!pipe || fd <= 0) return;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return;
    c->is_packet = is_packet;
}

void nwpipe_set_conn_ex(nwpipe_t *pipe, int fd, int ex) {
    if (!pipe || fd <= 0) return;
    conn_t *c = get_conn(pipe, fd);
    _LOG("nwpipe_set_conn_ex conn:%p", c);
    if (!c) return;
    c->ex = ex;
    _LOG("nwpipe_set_conn_ex conn ex:%d", c->ex);
}

int nwpipe_get_conn_ex(nwpipe_t *pipe, int fd) {
    if (!pipe || fd <= 0) return 0;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return 0;
    return c->ex;
}

int nwpipe_get_conn_type(nwpipe_t *pipe, int fd) {
    if (!pipe || fd <= 0) return 0;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return 0;
    return c->type;
}

int nwpipe_get_conn_status(nwpipe_t *pipe, int fd) {
    if (!pipe || fd <= 0) return 0;
    conn_t *c = get_conn(pipe, fd);
    if (!c) return 0;
    return c->status;
}