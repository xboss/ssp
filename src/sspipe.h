#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "ssp.h"

#define SSP_PACKET_HEAD_LEN 4
#define SSP_MAX_PAYLOAD_LEN (1024 * 2)
#define SSP_RECV_BUF_SIZE (SSP_MAX_PAYLOAD_LEN + SSP_PACKET_HEAD_LEN) * 5

typedef struct sspipe_ctx_s sspipe_ctx_t;
typedef struct sspipe_s sspipe_t;
typedef int (*sspipe_output_cb_t)(sspipe_t *pipe);
typedef void(*sspipe_free_user_cb_t)(void* user);

struct sspipe_s {
    int id;
    ssbuff_t* recv_buf;
    ssbuff_t* send_buf;
    sspipe_t* outer;
    int need_pack;
    sspipe_output_cb_t output_cb;
    void* user;
    sspipe_free_user_cb_t free_user_cb;
    sspipe_ctx_t* ctx;
    UT_hash_handle hh;
};

struct sspipe_ctx_s {
    sspipe_t* pipe_index;
    unsigned char* key;
    unsigned char* iv;
    char* pkt_buf;
    int max_pkt_buf_size;
    struct ev_loop* loop;
};

sspipe_ctx_t* sspipe_init(struct ev_loop* loop, const char* key, int key_len, const char* iv, int iv_len,
                          int max_pkt_buf_size);
void sspipe_free(sspipe_ctx_t* ctx);

sspipe_t* sspipe_get(sspipe_ctx_t* ctx, int id);
sspipe_t* sspipe_add(sspipe_ctx_t* ctx, int id, int need_pack, sspipe_output_cb_t output_cb,
                     void* user, sspipe_free_user_cb_t free_user_cb);
void sspipe_del(sspipe_t* pipe);
int sspipe_feed(sspipe_t* pipe, const char* buf, int len);
void sspipe_print_info(sspipe_ctx_t* ctx);

#endif /* _SSPIPE_H */