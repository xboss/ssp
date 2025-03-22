#ifndef _SSP_H
#define _SSP_H

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>
#include <sys/time.h>

#include "crypto.h"
#include "ssbuff.h"
#include "sslog.h"
#include "uthash.h"

#if !defined(INET_ADDRSTRLEN)
#define INET_ADDRSTRLEN 16
#endif  // INET_ADDRSTRLEN

#define _OK 0
#define _ERR -1

#define SSP_MODE_LOCAL 0
#define SSP_MODE_REMOTE 1
#define SSP_TICKET_SIZE (32)

#define SSP_CONNECT_TIMEOUT 5000

typedef struct {
    char listen_ip[INET_ADDRSTRLEN + 1];
    unsigned short listen_port;
    char target_ip[INET_ADDRSTRLEN + 1];
    unsigned short target_port;
    unsigned char key[AES_128_KEY_SIZE + 1];
    unsigned char iv[AES_BLOCK_SIZE + 1];
    char ticket[SSP_TICKET_SIZE + 1];
    int mode;
    size_t recv_buf_size;
    int connect_timeout;  // ms
    char log_file[256];
    int log_level;
} ssp_config_t;

#endif /* _SSP_H */