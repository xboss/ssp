#ifndef _SSPIPE_H
#define _SSPIPE_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "cipher.h"
#include "sslog.h"
#include "ssnet.h"
#include "uthash.h"

#define _OK 0
#define _ERR -1

#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

#define PACKET_HEAD_LEN 4

#define SSPIPE_MODE_LOCAL 0
#define SSPIPE_MODE_REMOTE 1

typedef struct {
    char* buf;  // 动态缓冲区
    int len;    // 当前缓冲长度
    int cap;    // 缓冲区容量
} ssbuffer_t;

ssbuffer_t* ssbuffer_init();
int ssbuffer_grow(ssbuffer_t* ssb, int len);
void ssbuffer_free(ssbuffer_t* ssb);

typedef struct {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    char target_ip[INET_ADDRSTRLEN + 1];
    unsigned short target_port;
    char key[CIPHER_KEY_LEN + 1];
    int mode;
    int timeout;
    int read_buf_size;
    char* log_file;
    int log_level;
} ssconfig_t;

typedef enum { SSCONN_TYPE_NONE = 0, SSCONN_TYPE_SERV, SSCONN_TYPE_CLI } ssconn_type_t;
typedef enum { PCONN_ST_NONE = 0, PCONN_ST_OFF, PCONN_ST_WAIT, PCONN_ST_ON } ssconn_st_t;
typedef struct {
    int fd;
    int cp_fd;
    ssconn_type_t type;
    ssconn_st_t status;
    ssbuffer_t* recv_buf;
    ssbuffer_t* send_buf;
    ssnet_t* net;
    UT_hash_handle hh;
} ssconn_t;

ssconn_t* ssconn_init(int fd, int cp_fd, ssconn_type_t type, ssconn_st_t status, ssnet_t* net);
void ssconn_free(ssconn_t* conn);
void ssconn_free_all();
ssconn_t* ssconn_get(int fd);
int ssconn_close(int fd);
int ssconn_close_all();
int ssconn_flush_send_buf(ssconn_t* cp_conn);


typedef struct {
    ssev_loop_t *loop;
    ssconfig_t *config;
    ssnet_t *net;
    int listen_fd;
} sspipe_t;

sspipe_t *sspipe_init(ssev_loop_t *loop, ssconfig_t *config);
void sspipe_free(sspipe_t *sspipe);

#endif /* _SSPIPE_H */