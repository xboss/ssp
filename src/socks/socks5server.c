#ifndef _POSIX_C_SOURCE
/* #define _POSIX_C_SOURCE 199506L */
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "socks.h"
#include "sslog.h"

struct socks_s {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    /*     int timeout;
        int read_buf_size; */
    char* log_file;
    int log_level;

    sspipe_t* pipe;
    ssev_loop_t* loop;
};
typedef struct socks_s socks_t;

static socks_t g_socks;

static void handle_exit(int sig) {
    _LOG("exit by signal %d ... ", sig);
    ssev_stop(g_socks.loop);
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

#define _USAGE fprintf(stderr, "Usage: %s <listen ip> <listen port> [log level] [log file]\n \tlog level: DEBUG|INFO|NOTICE|WARN|ERROR|FATAL", argv[0])

static int parse_param(int argc, char const* argv[]) {
    if (argc < 3) {
        return _ERR;
    }
    int len = strnlen(argv[1], INET_ADDRSTRLEN + 1);
    if (len >= INET_ADDRSTRLEN + 1) {
        fprintf(stderr, "Invalid listen ip:%s\n", g_socks.listen_ip);
        return _ERR;
    }

    memcpy(g_socks.listen_ip, argv[1], len);
    g_socks.listen_port = (unsigned short)atoi(argv[2]);
    if (g_socks.listen_port > 65535) {
        fprintf(stderr, "Invalid listen port:%u\n", g_socks.listen_port);
        return _ERR;
    }
    if (argc == 4) {
        len = 10;
        char* v = (char*)argv[3];
        if (strncmp(v, "DEBUG", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_DEBUG;
        } else if (strncmp(v, "INFO", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_INFO;
        } else if (strncmp(v, "NOTICE", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_NOTICE;
        } else if (strncmp(v, "WARN", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_WARN;
        } else if (strncmp(v, "ERROR", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_ERROR;
        } else if (strncmp(v, "FATAL", len) == 0) {
            g_socks.log_level = SSLOG_LEVEL_FATAL;
        } else {
            g_socks.log_level = SSLOG_LEVEL_FATAL;
            fprintf(stderr, "Invalid log level:%s, now default: FATAL\n", v);
        }
    }
    if (argc == 5) {
        len = strnlen(argv[4], 256);
        char* v = (char*)argv[4];
        if (len >= 256) {
            fprintf(stderr, "Invalid log file:%s\n \tpathname max length is 255", v);
            return _ERR;
        }
        _ALLOC(g_socks.log_file, char*, len + 1);
        memset(g_socks.log_file, 0, len + 1);
        memcpy(g_socks.log_file, v, len);
    }
    return _OK;
}

int main(int argc, char const* argv[]) {
    memset(&g_socks, 0, sizeof(socks_t));

    if (parse_param(argc, argv) != _OK) {
        _USAGE;
        return 1;
    }

    sslog_init(g_socks.log_file, g_socks.log_level);
    if (g_socks.log_file) free(g_socks.log_file);

    g_socks.loop = ssev_init();
    if (!g_socks.loop) {
        _LOG_E("init loop error.");
        return 1;
    }
    /* ssev_set_ev_timeout(g_socks.loop, g_socks.timeout); */

    g_socks.pipe = sspipe_init(g_socks.loop, 0, g_socks.listen_ip, g_socks.listen_port, NULL, on_socks_recv, on_socks_accept);
    if (!g_socks.pipe) {
        _LOG_E("init pipe error.");
        ssev_free(g_socks.loop);
        return 1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = signal_handler;
    sigaction(SIGPIPE, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    ssev_run(g_socks.loop);
    sspipe_free(g_socks.pipe);
    ssev_free(g_socks.loop);

    _LOG("Bye");
    sslog_free();
    return 0;
}