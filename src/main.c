#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199506L
#endif

#include <assert.h>
#include <ctype.h>
/* #include <netinet/ip.h> */
#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cipher.h"
#include "nwpipe.h"
#include "ssconf.h"
#include "ssev.h"
#include "sslog.h"

#ifdef SOCKS5
#include "dns_resolver.h"
#include "socks.h"
#endif

#define NWPIPE_MODE_LOCAL 0
#define NWPIPE_MODE_REMOTE 1
#define NWPIPE_MODE_SOCKS5 2

#define CONF_MAX_CHAR_PER_LINE 1024

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

struct config_s {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    char target_ip[INET_ADDRSTRLEN + 1];
    unsigned short target_port;
    char key[CIPHER_KEY_LEN + 1];
    int mode;
    int timeout;
    int read_buf_size;
    char *log_file;
    int log_level;
};
typedef struct config_s config_t;

static config_t g_conf;
static nwpipe_t *g_pipe;
static ssev_loop_t *g_loop;

static int load_conf(const char *conf_file, config_t *conf) {
    char *keys[] = {"mode",     "listen_ip", "listen_port",   "target_ip", "target_port",
                    "password", "timeout",   "read_buf_size", "log_file",  "log_level"};
    int keys_cnt = sizeof(keys) / sizeof(char *);
    ssconf_t *cf = ssconf_init(keys, keys_cnt);
    assert(cf);
    int rt = ssconf_load(cf, conf_file);
    if (rt != 0) return -1;
    conf->log_level = SSLOG_LEVEL_ERROR;
    char *v = NULL;
    int i;
    for (i = 0; i < keys_cnt; i++) {
        v = ssconf_get_value(cf, keys[i]);
        if (!v) {
            printf("'%s' does not exists in config file '%s'.\n", keys[i], conf_file);
            continue;
        }
        int len = strlen(v);
        if (strcmp("mode", keys[i]) == 0) {
            if (strcmp(v, "local") == 0) {
                conf->mode = NWPIPE_MODE_LOCAL;
            } else if (strcmp(v, "remote") == 0) {
                conf->mode = NWPIPE_MODE_REMOTE;
            } else if (strcmp(v, "socks5") == 0) {
                conf->mode = NWPIPE_MODE_SOCKS5;
            } else {
                conf->mode = -1;
            }
        } else if (strcmp("listen_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->listen_ip, v, len);
            }
        } else if (strcmp("listen_port", keys[i]) == 0) {
            conf->listen_port = (unsigned short)atoi(v);
        } else if (strcmp("target_ip", keys[i]) == 0) {
            if (len <= INET_ADDRSTRLEN) {
                memcpy(conf->target_ip, v, len);
            }
        } else if (strcmp("target_port", keys[i]) == 0) {
            conf->target_port = (unsigned short)atoi(v);
        } else if (strcmp("password", keys[i]) == 0) {
#ifndef SOCKS5
            pwd2key(conf->key, CIPHER_KEY_LEN, v, strlen(v));
#endif
        } else if (strcmp("timeout", keys[i]) == 0) {
            conf->timeout = atoi(v);
        } else if (strcmp("read_buf_size", keys[i]) == 0) {
            conf->read_buf_size = atoi(v);
        } else if (strcmp("log_file", keys[i]) == 0) {
            _ALLOC(conf->log_file, char *, len + 1);
            memset(conf->log_file, 0, len + 1);
            memcpy(conf->log_file, v, len);
        } else if (strcmp("log_level", keys[i]) == 0) {
            if (strcmp(v, "DEBUG") == 0) {
                conf->log_level = SSLOG_LEVEL_DEBUG;
            } else if (strcmp(v, "INFO") == 0) {
                conf->log_level = SSLOG_LEVEL_INFO;
            } else if (strcmp(v, "NOTICE") == 0) {
                conf->log_level = SSLOG_LEVEL_NOTICE;
            } else if (strcmp(v, "WARN") == 0) {
                conf->log_level = SSLOG_LEVEL_WARN;
            } else if (strcmp(v, "ERROR") == 0) {
                conf->log_level = SSLOG_LEVEL_ERROR;
            } else {
                conf->log_level = SSLOG_LEVEL_FATAL;
            }
        }
        printf("%s : %s\n", keys[i], v);
    }
    ssconf_free(cf);
    printf("------------\n");
    return 0;
}

int check_config(config_t *conf) {
    if (conf->listen_port > 65535) {
        fprintf(stderr, "Invalid listen_port:%u in configfile.\n", conf->listen_port);
        return -1;
    }
    if (conf->mode == NWPIPE_MODE_LOCAL || conf->mode == NWPIPE_MODE_REMOTE) {
        if (conf->target_port > 65535) {
            fprintf(stderr, "Invalid target_port:%u in configfile.\n", conf->target_port);
            return -1;
        }
    }
    if (conf->mode != NWPIPE_MODE_LOCAL && conf->mode != NWPIPE_MODE_REMOTE && conf->mode != NWPIPE_MODE_SOCKS5) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is 'remote'.\n", conf->mode);
        return -1;
    }
    return 0;
}

/* ---------- pipe callback ---------- */

static int on_pipe_recv(nwpipe_t *pipe, int fd, const char *buf, int len) {
    int cp_fd = pconn_get_couple_id(fd);
    if (cp_fd <= 0) {
        _LOG("couple does not exists. fd:%d", fd);
        return -1;
    }
    char *plain = (char *)buf;
    int plain_len = len;
#ifndef SOCKS5
    if (pconn_is_secret(fd)) {
        plain = aes_decrypt(g_conf.key, buf, len, &plain_len);
        _LOG("decrypt ");
    }
#endif
    char *cihper = plain;
    int cipher_len = plain_len;
#ifndef SOCKS5
    if (pconn_is_secret(cp_fd)) {
        cihper = aes_encrypt(g_conf.key, plain, plain_len, &cipher_len);
        _LOG("encrypt ");
        assert(cipher_len % 16 == 0);
    }
#endif
    int rt = nwpipe_send(pipe, cp_fd, cihper, cipher_len);
    _LOG("nwpipe_send rt:%d", rt);

    if (cihper && cihper != plain) free(cihper);
    if (plain && plain != buf) free(plain);

    if (rt != 0) {
        nwpipe_close_conn(pipe, fd);
        return -1;
    }
    return 0;
}

static int on_pipe_accept(nwpipe_t *pipe, int fd) {
    int is_cp_secret = 0;
    int is_cp_packet = 0;
    if (g_conf.mode == NWPIPE_MODE_LOCAL) {
        pconn_set_is_packet(fd, 0);
        pconn_set_is_secret(fd, 0);
        is_cp_secret = 1;
        is_cp_packet = 1;
    } else {
        pconn_set_is_packet(fd, 1);
        pconn_set_is_secret(fd, 1);
        is_cp_secret = 0;
        is_cp_packet = 0;
    }
    int cp_fd = nwpipe_connect(pipe, g_conf.target_ip, g_conf.target_port, fd, is_cp_secret, is_cp_packet);
    if (cp_fd <= 0) {
        nwpipe_close_conn(pipe, fd);
    }
    return 0;
}

static void handle_exit(int sig) {
    _LOG("exit by signal %d ... ", sig);
    ssev_stop(g_loop);
}

static void signal_handler(int sn) {
    _LOG("signal_handler sig:%d", sn);
    switch (sn) {
        case SIGQUIT:
        case SIGINT:
        case SIGTERM:
            handle_exit(sn);
            break;
        default:
            break;
    }
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }
    memset(&g_conf, 0, sizeof(config_t));
    int rt = load_conf(argv[1], &g_conf);
    if (rt != 0) return 1;
    if (check_config(&g_conf) != 0) return 1;
    sslog_init(g_conf.log_file, g_conf.log_level);
    if (g_conf.log_file) free(g_conf.log_file);
    pipe_recv_cb_t recv_cb = on_pipe_recv;
    pipe_accept_cb_t accept_cb = on_pipe_accept;
    g_loop = ssev_init();
    if (!g_loop) {
        _LOG_E("init loop error.");
        return 1;
    }
    ssev_set_ev_timeout(g_loop, g_conf.timeout);
#ifdef SOCKS5
    if (g_conf.mode == NWPIPE_MODE_SOCKS5) {
        _LOG("socks5 mode...");
        recv_cb = on_socks_recv;
        accept_cb = on_socks_accept;
        if (init_domain_resolver(g_loop) != 0) {
            _LOG_E("init domain resolver error.");
            return 1;
        }
    }
#endif

    g_pipe = nwpipe_init(g_loop, g_conf.read_buf_size, g_conf.listen_ip, g_conf.listen_port, recv_cb, accept_cb);
    if (!g_pipe) {
        _LOG_E("init pipe error.");
        ssev_free(g_loop);
#ifdef SOCKS5
        free_domain_resolver(g_loop);
#endif
        return 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = signal_handler;
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    ssev_run(g_loop);
#ifdef SOCKS5
    free_domain_resolver(g_loop);
#endif
    nwpipe_free(g_pipe);
    ssev_free(g_loop);

    _LOG("Bye");
    sslog_free();
    return 0;
}
