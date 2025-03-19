#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "ssp.h"

#define SSP_PACKET_HEAD_LEN 4
#define SSP_MAX_PAYLOAD_LEN (1024 * 2)
#define SSP_RECV_BUF_SIZE (SSP_MAX_PAYLOAD_LEN + SSP_PACKET_HEAD_LEN) * 5

typedef int (*sspipe_output_cb_t)(int id, void* user);
typedef struct sspipe_ctx_s sspipe_ctx_t;
typedef struct sspipe_s sspipe_t;

struct sspipe_s {
    int id;
    ssbuff_t* recv_buf;
    ssbuff_t* resp_buf;
    sspipe_t* outer;
    int need_pack;
    int is_activity;
    sspipe_output_cb_t output_cb;
    void* user;
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
sspipe_t* sspipe_add(sspipe_ctx_t* ctx, int id, int need_pack, int is_activity, sspipe_output_cb_t output_cb,
                     void* user);
void sspipe_del(sspipe_t* pipe);
int sspipe_feed(sspipe_t* pipe, const char* buf, int len);

//////////////////////////////
//////////////////////////////
//////////////////////////////
//////////////////////////////

// typedef enum { SSPIPE_TYPE_UNPACK = 0, SSPIPE_TYPE_PACK } sspipe_type_t;
// typedef int (*sspipe_output_cb_t)(int id, void* user);

// typedef struct sspipe_ctx_s sspipe_ctx_t;

// sspipe_ctx_t* sspipe_init(struct ev_loop* loop, const char* key, int key_len, const char* iv, int iv_len,
//                           int max_pkt_buf_size);
// void sspipe_free(sspipe_ctx_t* ctx);

// int sspipe_new(sspipe_ctx_t* ctx, int in_id, sspipe_type_t type, int is_activity, sspipe_output_cb_t output_cb,
//                void* user);
// int sspipe_bind(sspipe_ctx_t* ctx, int in_id, int out_id);
// int sspipe_unbind(sspipe_ctx_t* ctx, int in_id);
// int sspipe_get_bind_id(sspipe_ctx_t* ctx, int id);
// sspipe_type_t sspipe_get_type(sspipe_ctx_t* ctx, int id);
// void* sspipe_get_userdata(sspipe_ctx_t* ctx, int in_id);
// void sspipe_del(sspipe_ctx_t* ctx, int in_id);
// int sspipe_feed(sspipe_ctx_t* ctx, int in_id, const char* buf, int len);
// ssbuff_t* sspipe_take(sspipe_ctx_t* ctx, int id);
// void sspipe_print_info(sspipe_ctx_t* ctx);

#endif /* _SSPIPE_H */