
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ss.h"
#include "ssconf.h"
#include "sspipe.h"

static ssconfig_t g_conf;
static sspipe_t* g_pipe;

static int load_conf(const char* conf_file, ssconfig_t* conf) {
    char* keys[] = {"mode",     "listen_ip", "listen_port",   "target_ip", "target_port",
                    "password", "timeout",   "read_buf_size", "log_file",  "log_level"};
    int keys_cnt = sizeof(keys) / sizeof(char*);
    ssconf_t* cf = ssconf_init(keys, keys_cnt);
    assert(cf);
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
                conf->mode = SSPIPE_MODE_LOCAL;
            } else if (strcmp(v, "remote") == 0) {
                conf->mode = SSPIPE_MODE_REMOTE;
            }
            // else if (strcmp(v, "socks5") == 0) {
            //     conf->mode = SSPIPE_MODE_SOCKS5;
            // }
            else {
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
            pwd2key(conf->key, CIPHER_KEY_LEN, v, strlen(v));
        }
        // else if (strcmp("timeout", keys[i]) == 0) {
        //     conf->timeout = atoi(v);
        // }
        else if (strcmp("read_buf_size", keys[i]) == 0) {
            conf->read_buf_size = atoi(v);
        } else if (strcmp("log_file", keys[i]) == 0) {
            conf->log_file = (char*)calloc(1, len + 1);
            if (!conf->log_file) {
                perror("alloc error");
                exit(1);
            }
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
    return _OK;
}

static int check_config(ssconfig_t* conf) {
    if (conf->listen_port > 65535) {
        fprintf(stderr, "Invalid listen_port:%u in configfile.\n", conf->listen_port);
        return _ERR;
    }
    if (conf->mode == SSPIPE_MODE_LOCAL || conf->mode == SSPIPE_MODE_REMOTE) {
        if (conf->target_port > 65535) {
            fprintf(stderr, "Invalid target_port:%u in configfile.\n", conf->target_port);
            return _ERR;
        }
    }
    if (conf->mode != SSPIPE_MODE_LOCAL && conf->mode != SSPIPE_MODE_REMOTE) {
        fprintf(stderr, "Invalid mode:%d in configfile. local mode is 'local', remote mode is 'remote'.\n", conf->mode);
        return _ERR;
    }
    return _OK;
}

int main(int argc, char const* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        return 1;
    }
    memset(&g_conf, 0, sizeof(ssconfig_t));
    int rt = load_conf(argv[1], &g_conf);
    if (rt != _OK) return 1;
    if (check_config(&g_conf) != 0) return 1;
    sslog_init(g_conf.log_file, g_conf.log_level);
    if (g_conf.log_file) free(g_conf.log_file);

    g_pipe = sspipe_init(&g_conf);
    if (!g_pipe) {
        _LOG_E("init pipe error.");
        return 1;
    }

    rt = sstcp_start_server(g_pipe->server);
    if (rt != _OK) {
        _LOG_E("start server error.");
    }
    sstcp_stop_server(g_pipe->server);
    sspipe_free(g_pipe);
    sslog_free();
    printf("Bye\n");
    return 0;
}
