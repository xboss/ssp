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

// #ifndef _ALLOC
// #define _ALLOC(_p, _type, _size)   \
//     (_p) = (_type)malloc((_size)); \
//     if (!(_p)) {                   \
//         perror("alloc error");     \
//         exit(1);                   \
//     }
// #endif  // _ALLOC

#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

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
ssconn_t* ssconn_get(int fd);
// int ssconn_chg_status(ssconn_t* conn, ssconn_st_t status);
int ssconn_close(int fd);
// int ssconn_add_cp(ssconn_t* conn, int cp_fd);
// int ssconn_send(ssconn_t* conn, const char* buf, int len);
// int ssconn_recv(ssconn_t* conn, char* buf, int len);

#endif /* _SSPIPE_H */