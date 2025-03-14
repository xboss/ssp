#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "ssp.h"

#define SSP_PACKET_HEAD_LEN 4
#define SSP_MAX_PAYLOAD_LEN (1024 * 2)
#define SSP_RECV_BUF_SIZE (SSP_MAX_PAYLOAD_LEN + SSP_PACKET_HEAD_LEN) * 5

typedef enum { SSPIPE_TYPE_UNPACK = 0, SSPIPE_TYPE_PACK } sspipe_type_t;
typedef int (*sspipe_output_cb_t)(const char* buf, int len, int id, void* user);

typedef struct sspipe_ctx_s sspipe_ctx_t;

sspipe_ctx_t* sspipe_init(const char* key, int key_len, const char* iv, int iv_len, int max_pkt_buf_size);
int sspipe_new(sspipe_ctx_t* ctx, int in_id, sspipe_type_t type, sspipe_output_cb_t output_cb, void* user);
int sspipe_bind(sspipe_ctx_t* ctx, int in_id, int out_id);
// int sspipe_join(sspipe_ctx_t* ctx, int in_id, int out_id, sspipe_type_t type, sspipe_output_cb_t output_cb, ev_io *read_watcher, void* user);
void sspipe_del(sspipe_ctx_t* ctx, int in_id);
int sspipe_feed(sspipe_ctx_t* ctx, int in_id, const char* buf, int len);
// int sspipe_take(int in_id, ssbuff_t* out_buf);
void sspipe_free(sspipe_ctx_t* ctx);

#endif /* _SSPIPE_H */