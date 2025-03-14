#ifndef _SS_H
#define _SS_H

#include "crypto.h"
#include "sslog.h"

#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

#define _OK 0
#define _ERR -1

#define SSPIPE_MODE_LOCAL 0
#define SSPIPE_MODE_REMOTE 1
#define SSPIPE_TICKET_SIZE (32)

typedef struct {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    char target_ip[INET_ADDRSTRLEN + 1];
    unsigned short target_port;
    unsigned char key[AES_128_KEY_SIZE + 1];
    unsigned char iv[AES_BLOCK_SIZE + 1];
    char ticket[SSPIPE_TICKET_SIZE + 1];
    int mode;
    int send_timeout;  // 发送超时时间（毫秒）
    int recv_timeout;  // 接收超时时间（毫秒）
    char* log_file;
    int log_level;
} ssconfig_t;

#endif /* SS_H */