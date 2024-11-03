#include "sspipe.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>

/* #include "ilist.h" */
#include "cipher.h"
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

struct sspipe_s {
    ssnet_t* net;
    ssev_loop_t* loop;
    int server_fd;
    char* key;
    /* pipe_recv_cb_t on_pipe_recv; */
    pipe_accept_cb_t on_pipe_accept;
};

/* ---------- protocol ----------- */
#define PACKET_HEAD_LEN 4

static int pack(int payload_len, const char* payload, char** buf) {
    if (payload_len <= 0 || !payload) {
        return 0;
    }
    _ALLOC(*buf, char*, payload_len + PACKET_HEAD_LEN);
    memset(*buf, 0, payload_len + PACKET_HEAD_LEN);
    int n_payload_len = htonl(payload_len);
    memcpy(*buf, &n_payload_len, PACKET_HEAD_LEN);
    memcpy(*buf + PACKET_HEAD_LEN, payload, payload_len);
    return payload_len + PACKET_HEAD_LEN;
}

static int unpack(char** p, int len, int* payload_len) {
    _LOG("uppack len:%d", len);
    assert(p);
    assert(*p);
    assert(len > 0);
    if (len < PACKET_HEAD_LEN) {
        return _ERR;
    }
    *payload_len = ntohl(*(uint32_t*)(*p));
    if (*payload_len <= 0 || *payload_len > 65535) {
        /* TODO: debug */
        _LOG_E("unpack payload_len:%d error, len:%d", *payload_len, len);
    }
    /* assert(*payload_len > 0 && *payload_len < 65535); */

    if (len < *payload_len + PACKET_HEAD_LEN) {
        return _ERR;
    }
    *p += PACKET_HEAD_LEN;
    _LOG("uppack len:%d payload_len:%d ok.", len, *payload_len);
    return _OK;
}

/* --------------------- */

/**
 * @brief tcpsend, or stage
 *
 * @param net
 * @param fd
 * @param snd_buf
 * @param buf must be encrypted
 * @param len
 * @return int _ERR _OK
 */
static int flush_tcp_send(ssnet_t* net, int fd, stream_buf_t* snd_buf, const char* buf, int len) {
    _LOG("flush_tcp_send fd:%d status:%d type:%d", fd, pconn_get_status(fd), pconn_get_type(fd));
    assert(pconn_get_status(fd) == PCONN_ST_ON);
    assert(snd_buf);
    assert(buf);
    assert(len > 0);
    int rt = ssnet_tcp_send(net, fd, buf, len);
    if (rt == 0 || rt == -2) {
        _LOG("flush_tcp_send error fd:%d rt:%d len:%d", fd, rt, len);
        return _ERR;
    } else if (rt == -1) {
        /* pending */
        pconn_set_can_write(fd, 0);
        _LOG("flush_tcp_send pending send fd:%d len:%d", fd, len);
        sb_write(snd_buf, buf, len);
    } else if (rt < len) {
        /* remain */
        _LOG("flush_tcp_send remain send fd:%d len:%d", fd, rt);
        assert(rt > 0);
        sb_write(snd_buf, buf + rt, len - rt);
    }
    _LOG("flush_tcp_send ok. fd:%d", fd);
    return _OK;
}

static char* encrypt_and_pack(int fd, const char* buf, int len, char* key, int* pk_len) {
    char* cihper = (char*)buf;
    int cipher_len = len;
    char* pk_buf = (char*)cihper;
    *pk_len = cipher_len;
    if (pconn_is_secret(fd)) {
        assert(fd > 0);
        cihper = aes_encrypt(key, buf, len, &cipher_len);
        _LOG("encrypt ");
        assert(cipher_len % 16 == 0);
        *pk_len = pack(cipher_len, cihper, &pk_buf);
        free(cihper);
        assert(*pk_len >= 0);
    }
    return pk_buf;
}

/* ---------- callback ----------- */

static int on_recv(ssnet_t* net, int fd, const char* buf, int len, struct sockaddr* addr) {
    _LOG("sspipe on_recv fd:%d len:%d", fd, len);
    sspipe_t* pipe = (sspipe_t*)ssnet_get_userdata(net);
    assert(pipe);
    int cp_fd = pconn_get_couple_id(fd);
    if (cp_fd <= 0 || pconn_get_status(fd) <= PCONN_ST_OFF || pconn_get_status(cp_fd) <= PCONN_ST_OFF) {
        sspipe_close_conn(pipe, fd);
        return _ERR;
    }
    int rt = _ERR;
    stream_buf_t* rcv_buf = pconn_get_rcv_buf(fd);
    assert(rcv_buf != NULL);
    sb_write(rcv_buf, buf, len);
    int rlen = sb_get_size(rcv_buf);
    char* _ALLOC(rbuf, char*, rlen);
    memset(rbuf, 0, rlen);
    rt = sb_read_all(rcv_buf, rbuf, rlen);
    assert(rt == rlen);

    if (!pconn_is_secret(fd)) {
        rt = sspipe_send(pipe, cp_fd, rbuf, rlen);
        if (rt != _OK) sspipe_close_conn(pipe, fd);
        free(rbuf);
        return _OK;
    }
    char* p = rbuf;
    int rl = rlen;
    char* plain = NULL;
    int plain_len = 0;
    int payload_len = 0;
    while (rl > 0 && pconn_is_exist(fd)) {
        rt = unpack(&p, rl, &payload_len);
        if (rt != _OK) {
            assert(rcv_buf);
            assert(p);
            assert(rl > 0);
            sb_write(rcv_buf, p, rl);
            break;
        }

        {
            if (payload_len < 0 || payload_len > 65535) { /* TODO: debug */
                _LOG_E("on_recv payload_len:%d error rl:%d", payload_len, rl);
                sspipe_close_conn(pipe, fd);
                free(rbuf);
                return _OK;
            }
        }

        plain = p;
        plain_len = payload_len;
        if (pconn_is_secret(fd)) {
            plain = aes_decrypt(pipe->key, p, payload_len, &plain_len);
            _LOG("decrypt ");
        }
        rt = sspipe_send(pipe, cp_fd, plain, plain_len);
        if (rt != _OK) {
            sspipe_close_conn(pipe, fd);
            if (plain != p) free(plain);
            free(rbuf);
            return _ERR;
        }
        if (plain != p) free(plain);
        p += payload_len;
        rl -= payload_len + PACKET_HEAD_LEN;
    }
    free(rbuf);
    return _OK;
}

static int on_close(ssnet_t* net, int fd) {
    _LOG("on close fd:%d", fd);
    sspipe_t* pipe = (sspipe_t*)ssnet_get_userdata(net);
    sspipe_close_conn(pipe, fd);
    return _OK;
}

static int on_accept(ssnet_t* net, int fd) {
    _LOG("on_accept fd:%d", fd);
    sspipe_t* pipe = (sspipe_t*)ssnet_get_userdata(net);
    assert(pipe);
    int rt = pconn_init(fd, PCONN_TYPE_SERV, 0, sb_init(NULL, 0), sb_init(NULL, 0));
    if (rt != 0) return _ERR;
    rt = pconn_set_status(fd, PCONN_ST_ON);
    assert(rt == _OK);
    rt = pconn_set_can_write(fd, 1);
    assert(rt == 0);
    if (pipe->on_pipe_accept) pipe->on_pipe_accept(pipe, fd);
    return _OK;
}

static int on_connected(sspipe_t* pipe, int fd) {
    _LOG("on_connected fd:%d", fd);
    int cp_fd = pconn_get_couple_id(fd);
    if (cp_fd <= 0) {
        _LOG("on_connected fd:%d couple does not exist", fd);
        sspipe_close_conn(pipe, fd);
        return _ERR;
    }
    assert(pconn_get_type(cp_fd) == PCONN_TYPE_SERV);
    int rt = pconn_set_status(fd, PCONN_ST_ON);
    assert(rt == _OK);
    _LOG("on_connected ok. fd:%d", fd);
    return _OK;
}

static int on_writable(ssnet_t* net, int fd) {
    _LOG_W("on_writable fd:%d", fd);
    if (!pconn_is_exist(fd)) {
        _LOG("on_writable fd:%d does not exist, close", fd);
        ssnet_tcp_close(net, fd);
        return _ERR;
    }
    sspipe_t* pipe = (sspipe_t*)ssnet_get_userdata(net);
    assert(pipe);
    if (pconn_get_status(fd) == PCONN_ST_OFF) {
        _LOG("on_writable fd:%d is off, close", fd);
        sspipe_close_conn(pipe, fd);
        return _ERR;
    }
    assert(pconn_get_type(fd) != PCONN_TYPE_NONE);
    int rt = _OK;
    if (pconn_get_status(fd) == PCONN_ST_READY && pconn_get_type(fd) == PCONN_TYPE_CLI) rt = on_connected(pipe, fd);
    if (rt == _OK) {
        rt = pconn_set_can_write(fd, 1);
        assert(rt == 0);
        if (pconn_get_status(fd) == PCONN_ST_ON) {
            stream_buf_t* snd_buf = pconn_get_snd_buf(fd);
            assert(snd_buf);
            int len = sb_get_size(snd_buf);
            if (len > 0) {
                char* _ALLOC(buf, char*, len);
                sb_read_all(snd_buf, buf, len);
                rt = flush_tcp_send(net, fd, snd_buf, buf, len);
                free(buf);
                if (rt != _OK) {
                    sspipe_close_conn(pipe, fd);
                }
            }
        }
    }
    return rt;
}

/* static int update(ssev_loop_t *loop, void *ud) {
    ssnet_t *net = (ssnet_t *)ud;
    assert(net);
    sspipe_t *pipe = (sspipe_t *)ssnet_get_userdata(net);
    assert(pipe);
    return 0;
} */

static void free_close_cb(int id, void* u) {
    ssnet_t* net = (ssnet_t*)u;
    assert(net);
    ssnet_tcp_close(net, id);
}

/* ---------- api ----------- */

sspipe_t* sspipe_init(ssev_loop_t* loop, int read_buf_size, const char* listen_ip, unsigned short listen_port, const char* key, /* pipe_recv_cb_t on_pipe_recv, */ pipe_accept_cb_t on_pipe_accept) {
    if (!listen_ip || listen_port <= 0) return NULL;
    sspipe_t* _ALLOC(pipe, sspipe_t*, sizeof(sspipe_t));
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
    pipe->key = (char*)key;
    /* pipe->on_pipe_recv = on_pipe_recv; */
    pipe->on_pipe_accept = on_pipe_accept;
    return pipe;
}

void sspipe_free(sspipe_t* pipe) {
    if (!pipe) return;
    pconn_free_all(pipe->net, free_close_cb);
    ssnet_free(pipe->net);
    free(pipe);
    _LOG("sspipe free ok.");
}

void sspipe_close_conn(sspipe_t* pipe, int fd) {
    if (!pipe || fd <= 0) return;
    if (!pconn_is_exist(fd)) return;
    int cp_fd = pconn_get_couple_id(fd);

    /* TODO: debug */
    pconn_type_t type = pconn_get_type(fd);
    pconn_st_t st = pconn_get_status(fd);
    pconn_type_t cp_type = pconn_get_type(cp_fd);
    pconn_st_t cp_st = pconn_get_status(cp_fd);

    pconn_set_status(fd, PCONN_ST_OFF);
    ssnet_tcp_close(pipe->net, fd);
    pconn_free(fd);
    _LOG_W("sspipe_close_conn fd:%d type:%d st:%d", fd, type, st);
    if (cp_fd > 0) {
        pconn_set_status(cp_fd, PCONN_ST_OFF);
        ssnet_tcp_close(pipe->net, cp_fd);
        pconn_free(cp_fd);
        _LOG_W("sspipe_close_conn cp_fd:%d cp_type:%d cp_st:%d", cp_fd, cp_type, cp_st);
    }
}

int sspipe_connect(sspipe_t* pipe, const char* ip, unsigned short port, int serv_fd, int is_secret) {
    if (!pipe || port <= 0 || !ip || serv_fd <= 0) return _ERR;
    if (!pconn_is_exist(serv_fd)) {
        _LOG("sspipe_connect serv_fd:%d does not exist", serv_fd);
        return _ERR;
    }
    if (pconn_get_couple_id(serv_fd) > 0) {
        _LOG("sspipe_connect pconn_get_couple_id serv_fd:%d, cli_id:%d", serv_fd, pconn_get_couple_id(serv_fd));
        return _ERR;
    }
    if (pconn_get_type(serv_fd) != PCONN_TYPE_SERV) {
        _LOG_E("sspipe_connect serv_fd:%d does not server", serv_fd);
        return _ERR;
    }
    int fd = ssnet_tcp_connect(pipe->net, ip, port);
    _LOG("sspipe_connect fd:%d serv_fd:%d", fd, serv_fd);
    if (fd <= 0) {
        _LOG("sspipe_connect fd:%d serv_fd:%d error", fd, serv_fd);
        return _ERR;
    }
    int rt = pconn_init(fd, PCONN_TYPE_CLI, serv_fd, sb_init(NULL, 0), sb_init(NULL, 0));
    assert(rt == 0);
    rt = pconn_set_status(fd, PCONN_ST_READY);
    assert(rt == _OK);
    rt = pconn_set_is_secret(fd, is_secret);
    assert(rt == 0);
    rt = pconn_add_cli_id(serv_fd, fd);
    assert(rt == 0);
    return fd;
}

/**
 * @brief encrypt, stage or flush. Not responsible for closing connections
 *
 * @param pipe
 * @param fd
 * @param buf plain text
 * @param len
 * @return int _OK or _ERR
 */
int sspipe_send(sspipe_t* pipe, int fd, const char* buf, int len) {
    if (!pipe || fd <= 0 || !buf || len <= 0) return _ERR;
    pconn_st_t st = pconn_get_status(fd);
    if (st <= PCONN_ST_OFF) return _ERR;
    stream_buf_t* snd_buf = pconn_get_snd_buf(fd);
    assert(snd_buf);
    int pk_len;
    char* pk_buf = encrypt_and_pack(fd, buf, len, pipe->key, &pk_len);
    int rt = _OK;
    if (pconn_get_status(fd) == PCONN_ST_READY) {
        sb_write(snd_buf, pk_buf, pk_len);
        if (pk_buf != buf) free(pk_buf);
        return _OK;
    }

    int wlen = sb_get_size(snd_buf);
    if (wlen == 0 && pconn_can_write(fd)) {
        rt = flush_tcp_send(pipe->net, fd, snd_buf, pk_buf, pk_len);
        if (pk_buf != buf) free(pk_buf);
        return rt;
    }
    sb_write(snd_buf, pk_buf, pk_len);
    wlen = sb_get_size(snd_buf);
    if (pconn_can_write(fd)) {
        char* _ALLOC(wbuf, char*, wlen);
        memset(wbuf, 0, wlen);
        sb_read_all(snd_buf, wbuf, wlen);
        rt = flush_tcp_send(pipe->net, fd, snd_buf, wbuf, wlen);
        free(wbuf);
    }
    if (pk_buf != buf) free(pk_buf);
    _LOG("sspipe_send buf fd:%d rt:%d", fd, rt);
    return rt;
}
