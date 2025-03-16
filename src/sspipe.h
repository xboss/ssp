#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "ssp.h"

#define SSP_PACKET_HEAD_LEN 4
#define SSP_MAX_PAYLOAD_LEN (1024 * 4)
#define SSP_RECV_BUF_SIZE (SSP_MAX_PAYLOAD_LEN + SSP_PACKET_HEAD_LEN) * 5

typedef enum { SSPIPE_TYPE_UNPACK = 0, SSPIPE_TYPE_PACK } sspipe_type_t;
typedef int (*sspipe_output_cb_t)(int id, void* user);



typedef struct sspipe_ctx_s sspipe_ctx_t;

sspipe_ctx_t* sspipe_init(struct ev_loop *loop, const char* key, int key_len, const char* iv, int iv_len, int max_pkt_buf_size);
void sspipe_free(sspipe_ctx_t* ctx);

int sspipe_new(sspipe_ctx_t* ctx, int in_id, sspipe_type_t type, int is_activity, sspipe_output_cb_t output_cb, void* user);
int sspipe_bind(sspipe_ctx_t* ctx, int in_id, int out_id);
int sspipe_unbind(sspipe_ctx_t* ctx, int in_id);
int sspipe_get_bind_id(sspipe_ctx_t* ctx, int id);
void* sspipe_get_userdata(sspipe_ctx_t* ctx, int in_id);
// ev_io *sspipe_get_read_watcher(sspipe_ctx_t* ctx, int in_id);
// ev_io *sspipe_get_write_watcher(sspipe_ctx_t* ctx, int in_id);
void sspipe_del(sspipe_ctx_t* ctx, int in_id);
int sspipe_feed(sspipe_ctx_t* ctx, int in_id, const char* buf, int len);
ssbuff_t* sspipe_take(sspipe_ctx_t* ctx, int id);
// int sspipe_set_activity(sspipe_ctx_t* ctx, int in_id, int is_activity);
// int sspipe_is_activity(sspipe_ctx_t* ctx, int in_id);
void sspipe_print_info(sspipe_ctx_t* ctx);

#endif /* _SSPIPE_H */