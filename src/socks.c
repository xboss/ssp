#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "socks.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "dns_resolver.h"

#ifdef DEBUG
#include "debug.h"
#endif

#ifndef _LOG
#define _LOG(fmt, ...)
#endif

#define SS5_VER 0x05U
#define SS5_AUTH_NP_VER 0x01U
#define SS5_CMD_CONNECT 0x01U
#define SS5_CMD_BIND 0x02U
#define SS5_CMD_UDP_ASSOCIATE 0x03U

#define SS5_ATYP_IPV4 0x01U
#define SS5_ATYP_DOMAIN 0x03U
#define SS5_ATYP_IPV6 0x04U

/*
REP: 回复请求的状态
0x00 成功代理
0x01 SOCKS服务器出现了错误
0x02 不允许的连接
0x03 找不到网络
0x04 找不到主机
0x05 连接被拒
0x06 TTL超时
0x07 不支持的CMD
0x08 不支持的ATYP
 */
#define SS5_REP_OK 0x00U
#define SS5_REP_ERR 0x01U
#define SS5_REP_HOST_ERR 0x04U

#define SS5_PHASE_AUTH 1
#define SS5_PHASE_REQ 2
#define SS5_PHASE_DATA 3
#define SS5_PHASE_AUTH_NP 4

/* 1 + 1 + 1 + 1 + 257 + 2 */
#define SS5_REQ_ACK_MAX_SZ 263
#define SS5_DOMAIN_NAME_MAX_SZ 256

/* static uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
} */

static void domain_cb(domain_req_t *req) {
    if (!req) {
        _LOG("req is NULL in domain_cb");
        return;
    }
    _LOG("dns id:%d resp:%d name:%s ip:%s", get_domain_req_id(req), get_domain_req_resp(req), get_domain_req_name(req),
         get_domain_req_ip(req));
    int src_fd = get_domain_req_id(req);
    nwpipe_t *pipe = get_domain_req_userdata(req);
    if (src_fd > 0 && pipe && get_domain_req_resp(req) == 0) {
        int src_status = nwpipe_get_conn_status(pipe, src_fd);
        if (src_status == 0) return;
        char *name = get_domain_req_name(req);
        int d_len = strlen(get_domain_req_name(req));
        assert(d_len > 0 && d_len < SS5_REQ_ACK_MAX_SZ);
        char *ip = get_domain_req_ip(req);
        unsigned short port = get_domain_req_port(req);
        char ack[SS5_REQ_ACK_MAX_SZ];
        memset(ack, 0, SS5_REQ_ACK_MAX_SZ);
        ack[0] = SS5_VER;
        ack[1] = SS5_REP_OK;
        ack[3] = SS5_ATYP_DOMAIN;
        ack[4] = d_len & 0xff;
        _LOG("domain_cb d_len:%d name:%s", d_len, name);
        memcpy(ack + 5, name, d_len);
        unsigned short nport = htons(port);
        /* ack[5 + d_len] = htons(port); */
        memcpy(ack + 5 + d_len, &nport, 2);

        int cp_fd = nwpipe_connect(pipe, ip, port, src_fd, 0, 0);
        if (cp_fd <= 0) {
            nwpipe_close_conn(pipe, src_fd);
            nwpipe_close_conn(pipe, cp_fd); /* TODO: */
            /* free_domain_req(req); */
            return;
        }

        /*         int i;
                printf("ack:");
                for (i = 0; i < 7 + d_len + 1; i++) {
                    printf("%.2X ", ack[i]);
                }
                printf("\n"); */

        int rt = nwpipe_send(pipe, src_fd, ack, 7 + d_len);
        if (rt == -1) {
            nwpipe_close_conn(pipe, src_fd);
            nwpipe_close_conn(pipe, cp_fd); /* TODO: */
            /* free_domain_req(req); */
            return;
        }
        _LOG("dns socks5 nwpipe_send ok fd:%d", src_fd);
        nwpipe_set_conn_ex(pipe, src_fd, SS5_PHASE_DATA);
    } else {
        _LOG("dns domain_cb error fd:%d", src_fd);
        nwpipe_close_conn(pipe, src_fd);
    }
}

static void ss5_auth(nwpipe_t *pipe, int fd, const char *buf, int len) {
    if (buf[0] != SS5_VER || len < 3) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    int nmethods = (int)buf[1];
    if (nmethods > 6) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    char ack[2] = {SS5_VER, 0x00};
    int i, rt = 0, phase = 0;
    for (i = 0; i < nmethods; i++) {
        if (buf[2 + i] == 0x00) {
            /* NO AUTHENTICATION REQUIRED */
            phase = SS5_PHASE_REQ;
            break;
        } else if (buf[2 + i] == 0x02) {
            /* USERNAME/PASSWORD */
            ack[1] = 0x02;
            phase = SS5_PHASE_AUTH_NP;
            break;
        } else {
            /* No acceptable method */
            ack[1] = 0xff;
        }
    }
    rt = nwpipe_send(pipe, fd, ack, sizeof(ack));
    if (rt == -1) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    nwpipe_set_conn_ex(pipe, fd, phase);
}

static void ss5_auth_np(nwpipe_t *pipe, int fd, const char *buf, int len) {
    if (buf[0] != SS5_AUTH_NP_VER || len < 5) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    int name_len = buf[1];
    if (name_len <= 0) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    int pwd_len = buf[2 + name_len];
    if (pwd_len < 0) {
        nwpipe_close_conn(pipe, fd);
        return;
    }

    int auth_rt = 0;
    /* TODO: check name and password */

    char ack[2] = {SS5_AUTH_NP_VER, 0x00};
    if (auth_rt != 0) {
        ack[1] = 0x01;
    }
    int rt = nwpipe_send(pipe, fd, ack, sizeof(ack));
    if (rt == -1) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    nwpipe_set_conn_ex(pipe, fd, SS5_PHASE_REQ);
}

static void ss5_req(nwpipe_t *pipe, int fd, const char *buf, int len) {
    if (buf[0] != SS5_VER || len < 7) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    u_char cmd = buf[1];
    if (cmd == SS5_CMD_BIND || cmd == SS5_CMD_UDP_ASSOCIATE) {
        /* TODO: support bind and udp associate */
        _LOG("socks5: now only 'connect' command is supported.");
    }
    if (cmd != SS5_CMD_CONNECT) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    char ack[SS5_REQ_ACK_MAX_SZ];
    assert(SS5_REQ_ACK_MAX_SZ >= len);
    memcpy(ack, buf, len);
    char rep = 0x00;
    unsigned short port = 0;
    char ip[INET_ADDRSTRLEN];
    memset(ip, 0, INET_ADDRSTRLEN);
    u_char atyp = buf[3];
    if (atyp == SS5_ATYP_IPV4) {
        struct in_addr addr;
        addr.s_addr = *(uint32_t *)(buf + 4);
        char *ipp = inet_ntoa(addr);
        memcpy(ip, ipp, strlen(ipp));
        port = ntohs(*(uint16_t *)(buf + 8));
        _LOG("socks5 ip:%s:%u", ip, port);
    } else if (atyp == SS5_ATYP_DOMAIN) {
        int d_len = (int)(buf[4] & 0xff);
        assert(d_len <= SS5_DOMAIN_NAME_MAX_SZ);
        port = ntohs(*(uint16_t *)(buf + 4 + d_len + 1));
        domain_req_t *req = init_domain_req(fd, buf + 5, d_len, domain_cb, port, pipe);
        if (!req) {
            nwpipe_close_conn(pipe, fd);
            return;
        }
        int rt = resolve_domain(req);
        if (rt != 0) {
            nwpipe_close_conn(pipe, fd);
            return;
        }
        return;
    } else if (atyp == SS5_ATYP_IPV6) {
        _LOG("socks5 ipv6 type");
        /* TODO: support ipv6 */
        return;
    } else {
        _LOG("socks5 request error atyp");
        return;
    }

    int cp_fd = nwpipe_connect(pipe, ip, port, fd, 0, 0);
    if (cp_fd <= 0) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    ack[1] = rep;
    int rt = nwpipe_send(pipe, fd, ack, len);
    if (rt == -1) {
        nwpipe_close_conn(pipe, fd);
        return;
    }
    _LOG("socks5 nwpipe_send ok fd:%d", fd);
    nwpipe_set_conn_ex(pipe, fd, SS5_PHASE_DATA);
}

static int on_backend_recv(nwpipe_t *pipe, int fd, const char *buf, int len) {
    int cp_fd = nwpipe_get_couple_fd(pipe, fd);
    if (cp_fd <= 0) {
        return -1;
    }

    int rt = nwpipe_send(pipe, cp_fd, buf, len);
    if (rt == -1) {
        /* error */
        nwpipe_close_conn(pipe, cp_fd);
        return -1;
    }
    return 0;
}

static int on_front_recv(nwpipe_t *pipe, int fd, const char *buf, int len) {
    int phase = nwpipe_get_conn_ex(pipe, fd);
    if (phase == SS5_PHASE_AUTH) {
        ss5_auth(pipe, fd, buf, len);
    } else if (phase == SS5_PHASE_REQ) {
        ss5_req(pipe, fd, buf, len);
    } else if (phase == SS5_PHASE_AUTH_NP) {
        ss5_auth_np(pipe, fd, buf, len);
    } else if (phase == SS5_PHASE_DATA) {
        int cp_fd = nwpipe_get_couple_fd(pipe, fd);
        if (cp_fd <= 0) {
            return -1;
        }
        int rt = nwpipe_send(pipe, cp_fd, buf, len);
        if (rt == -1) {
            /* error */
            nwpipe_close_conn(pipe, cp_fd);
            return -1;
        }
    } else {
        /* error */
        _LOG("socks5 phase error %d", phase);
        nwpipe_close_conn(pipe, fd);
        return -1;
    }

    return 0;
}

int on_socks_recv(nwpipe_t *pipe, int fd, const char *buf, int len) {
    if (!pipe || fd <= 0 || !buf || len <= 0) {
        return -1;
    }
    int conn_type = nwpipe_get_conn_type(pipe, fd);
    if (conn_type == NWPIPE_CONN_TYPE_FR) {
        return on_front_recv(pipe, fd, buf, len);
    } else if (conn_type == NWPIPE_CONN_TYPE_BK) {
        return on_backend_recv(pipe, fd, buf, len);
    } else {
        _LOG("connection type error");
        return -1;
    }
    return 0;
}

int on_socks_accept(nwpipe_t *pipe, int fd) {
    nwpipe_set_conn_ex(pipe, fd, SS5_PHASE_AUTH);
    return 0;
}
