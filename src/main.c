
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssconfig.h"
#include "ssp.h"
#include "ssp_server.h"

static ssp_config_t g_conf;
static ssp_server_t* g_ssp_server = NULL;
struct ev_loop* g_loop = NULL;

static int check_config(ssp_config_t* conf) {
    if (conf->mode != SSP_MODE_LOCAL && conf->mode != SSP_MODE_REMOTE) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is 'remote'.\n", conf->mode);
        return _ERR;
    }
    if (conf->ticket[0] == '\0' || conf->ticket[SSP_TICKET_SIZE] != '\0') {
        fprintf(stderr, "Invalid ticket in configfile.\n");
        return _ERR;
    }
    if (conf->listen_ip[0] == '\0') {
        fprintf(stderr, "Invalid listen_ip in configfile.\n");
        return _ERR;
    }
    if (conf->mode == SSP_MODE_LOCAL && conf->target_ip[0] == '\0') {
        fprintf(stderr, "Invalid target_ip in configfile.\n");
        return _ERR;
    }
    if (conf->listen_port > 65535) {
        fprintf(stderr, "Invalid listen_port:%u in configfile.\n", conf->listen_port);
        return _ERR;
    }
    if (conf->mode == SSP_MODE_LOCAL || conf->mode == SSP_MODE_REMOTE) {
        if (conf->target_port > 65535) {
            fprintf(stderr, "Invalid target_port:%u in configfile.\n", conf->target_port);
            return _ERR;
        }
    }
    // set default values
    if (conf->connect_timeout <= 0) {
        conf->connect_timeout = SSP_CONNECT_TIMEOUT;
    }
    if (conf->recv_buf_size <= 0 || conf->recv_buf_size > 999999999) {
        conf->recv_buf_size = SSP_RECV_BUF_SIZE;
    }
    // conf->max_payload_size = conf->recv_buf_size - SSP_PACKET_HEAD_LEN;
    return _OK;
}

int config_handler(const char *key, const char *value, size_t line_no, void *user) {
    ssp_config_t *conf = (ssp_config_t *)user;
    assert(conf);
    // {"mode", "listen_ip", "listen_port", "target_ip", "target_port", "password", "log_file", "log_level", "ticket", "connect_timeout", "recv_buf_size"};
    if (strcmp(key, "mode") == 0) {
        if (strcmp(value, "local") == 0) {
            conf->mode = SSP_MODE_LOCAL;
        } else if (strcmp(value, "remote") == 0) {
            conf->mode = SSP_MODE_REMOTE;
        } else {
            conf->mode = -1;
        }
    }
    if (strcmp(key, "listen_ip") == 0) {
        if (strlen(value) <= INET_ADDRSTRLEN) {
            strncpy(conf->listen_ip, value, INET_ADDRSTRLEN);
        }
    }
    if (strcmp(key, "listen_port") == 0) {
        conf->listen_port = (unsigned short)atoi(value);
    }
    if (strcmp(key, "target_ip") == 0) {
        if (strlen(value) <= INET_ADDRSTRLEN) {
            strncpy(conf->target_ip, value, INET_ADDRSTRLEN);
        }
    }
    if (strcmp(key, "target_port") == 0) {
        conf->target_port = (unsigned short)atoi(value);
    }
    if (strcmp(key, "password") == 0) {
        memcpy(conf->key, value, strnlen(value, AES_128_KEY_SIZE));
    }
    if (strcmp(key, "ticket") == 0) {
        strncpy(conf->ticket, value, SSP_TICKET_SIZE);
    }
    if (strcmp(key, "connect_timeout") == 0) {
        conf->connect_timeout = atoi(value);
    }
    if (strcmp(key, "recv_buf_size") == 0) {
        conf->recv_buf_size = atoi(value);
    }
    if (strcmp(key, "log_file") == 0) {
        strncpy(conf->log_file, value, sizeof(conf->log_file) - 1);
    }
    if (strcmp(key, "log_level") == 0) {
        if (strcmp(value, "DEBUG") == 0) {
            conf->log_level = SSLOG_LEVEL_DEBUG;
        } else if (strcmp(value, "INFO") == 0) {
            conf->log_level = SSLOG_LEVEL_INFO;
        } else if (strcmp(value, "NOTICE") == 0) {
            conf->log_level = SSLOG_LEVEL_NOTICE;
        } else if (strcmp(value, "WARN") == 0) {
            conf->log_level = SSLOG_LEVEL_WARN;
        } else if (strcmp(value, "ERROR") == 0) {
            conf->log_level = SSLOG_LEVEL_ERROR;
        } else {
            conf->log_level = SSLOG_LEVEL_FATAL;
        }
    }
    printf("%s:%s\n", key, value);
    return 0;
}

static void sig_cb(struct ev_loop* loop, ev_signal* w, int revents) {
    _LOG("sig_cb signal:%d", w->signum);
    if (w->signum == SIGPIPE) {
        return;
    }
    if (w->signum == SIGINT) {
        if (g_ssp_server) ssp_server_stop(g_ssp_server);
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    if (w->signum == SIGUSR1) {
        if (g_ssp_server) ssp_monitor(g_ssp_server);
        return;
    }
}

int main(int argc, char const* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }
    memset(&g_conf, 0, sizeof(ssp_config_t));
    if (sscf_parse(argv[1], config_handler, &g_conf) != _OK) return 1;
    if (check_config(&g_conf) != _OK) return 1;

    sslog_init(g_conf.log_file, g_conf.log_level);
    strcpy((char*)g_conf.iv, "bewatermyfriend.");

    g_loop = EV_DEFAULT;

    ev_signal sig_pipe_watcher;
    ev_signal_init(&sig_pipe_watcher, sig_cb, SIGPIPE);
    ev_signal_start(g_loop, &sig_pipe_watcher);

    ev_signal sig_int_watcher;
    ev_signal_init(&sig_int_watcher, sig_cb, SIGINT);
    ev_signal_start(g_loop, &sig_int_watcher);

    ev_signal sig_usr1_watcher;
    ev_signal_init(&sig_usr1_watcher, sig_cb, SIGUSR1);
    ev_signal_start(g_loop, &sig_usr1_watcher);

    g_ssp_server = ssp_server_init(g_loop, &g_conf);
    if (!g_ssp_server) {
        _LOG_E("init ssp server error.");
        return 1;
    }

    int ret = ssp_server_start(g_ssp_server);
    if (ret != _OK) {
        ssp_server_free(g_ssp_server);
        _LOG_E("start ssp server error.");
    }

    ev_run(g_loop, 0);

    ssp_server_free(g_ssp_server);
    sslog_free();
    printf("Bye\n");
    return 0;
}
