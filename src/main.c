
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ssconf.h"
#include "ssp.h"
#include "ssp_server.h"

static ssconfig_t g_conf;
static ssp_server_t* g_ssp_server = NULL;
struct ev_loop* g_loop = NULL;

static int load_conf(const char* conf_file, ssconfig_t* conf) {
    char* keys[] = {"mode", "listen_ip", "listen_port", "target_ip", "target_port", "password", "log_file", "log_level", "ticket"};
    int keys_cnt = sizeof(keys) / sizeof(char*);
    ssconf_t* cf = ssconf_init(1024, 1024);
    if (!cf) return _ERR;
    int rt = ssconf_load(cf, conf_file);
    if (rt != 0) return _ERR;
    conf->log_level = SSLOG_LEVEL_ERROR;
    char* v = NULL;
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
                conf->mode = SSP_MODE_LOCAL;
            } else if (strcmp(v, "remote") == 0) {
                conf->mode = SSP_MODE_REMOTE;
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
            memcpy(conf->key, v, strnlen(v, AES_128_KEY_SIZE));
        } else if (strcmp("ticket", keys[i]) == 0) {
            memcpy(conf->ticket, v, strnlen(v, SSP_TICKET_SIZE));
        } else if (strcmp("log_file", keys[i]) == 0) {
            len = len > (sizeof(conf->log_file) - 1) ? (sizeof(conf->log_file) - 1) : len;
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
        printf("%s:%s\n", keys[i], v);
    }
    ssconf_free(cf);
    printf("------------\n");
    return _OK;
}

static int check_config(ssconfig_t* conf) {
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
    if (conf->mode != SSP_MODE_LOCAL && conf->mode != SSP_MODE_REMOTE) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is 'remote'.\n", conf->mode);
        return _ERR;
    }
    return _OK;
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
    memset(&g_conf, 0, sizeof(ssconfig_t));
    int ret = load_conf(argv[1], &g_conf);
    if (ret != _OK) return 1;
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

    ret = ssp_server_start(g_ssp_server);
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
