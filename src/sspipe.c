#include "sspipe.h"

#include <arpa/inet.h>

inline static void free_sspipe(sspipe_t* pipe) {
    if (!pipe) {
        return;
    }
    _LOG("free pipe. id:%d", pipe->id);
    if (pipe->recv_buf) {
        ssbuff_free(pipe->recv_buf);
        pipe->recv_buf = NULL;
    }
    if (pipe->send_buf) {
        ssbuff_free(pipe->send_buf);
        pipe->send_buf = NULL;
    }
    pipe->id = 0;
    free(pipe);
}

inline static sspipe_t* new_sspipe(int id) {
    sspipe_t* pipe = (sspipe_t*)calloc(1, sizeof(sspipe_t));
    if (pipe == NULL) {
        _LOG_E("new_pipe: calloc failed");
        return NULL;
    }
    pipe->id = id;
    pipe->recv_buf = ssbuff_init(0);
    if (pipe->recv_buf == NULL) {
        _LOG_E("new_pipe: ssbuff_init failed");
        free_sspipe(pipe);
        return NULL;
    }
    pipe->send_buf = ssbuff_init(0);
    if (pipe->send_buf == NULL) {
        _LOG_E("new_pipe: ssbuff_init failed");
        free_sspipe(pipe);
        return NULL;
    }
    return pipe;
}

static int pack(sspipe_t* pipe) {
    assert(pipe);
    assert(pipe->outer);
    sspipe_ctx_t* ctx = pipe->ctx;
    uint32_t payload_len = 0;
    int remaining = pipe->recv_buf->len;
    size_t cipher_len = 0;
    int pkt_len = 0;
    while (remaining > 0) {
        // pack and send
        payload_len = remaining > SSP_MAX_PAYLOAD_LEN ? SSP_MAX_PAYLOAD_LEN : remaining;
        uint32_t payload_len_net = htonl(payload_len);
        memcpy(ctx->pkt_buf, &payload_len_net, SSP_PACKET_HEAD_LEN);
        pkt_len += SSP_PACKET_HEAD_LEN;
        // encrypt
        if (ctx->key && ctx->iv) {
            if (crypto_encrypt(ctx->key, ctx->iv, (const unsigned char*)pipe->recv_buf->buf + (pipe->recv_buf->len - remaining), payload_len, (unsigned char*)ctx->pkt_buf + SSP_PACKET_HEAD_LEN,
                               &cipher_len) != 0) {
                _LOG_E("pack crypto_encrypt failed");
                return _ERR;
            }
            _LOG("pack crypto_encrypt ok.");
            assert(cipher_len == payload_len);
            pkt_len += cipher_len;
        } else {
            memcpy(ctx->pkt_buf + SSP_PACKET_HEAD_LEN, pipe->recv_buf->buf + (pipe->recv_buf->len - remaining), payload_len);
            pkt_len += payload_len;
        }
        // sspipe_t* out_pipe = get_sspipe(ctx, pipe->out_id);
        // if (!out_pipe) {
        //     _LOG_E("pack get_sspipe out_id:%d failed", pipe->out_id);
        //     return _ERR;
        // }
        ssbuff_append(pipe->outer->send_buf, ctx->pkt_buf, pkt_len);
        pkt_len = 0;
        _LOG("pack to target ok. payload_len:%d", payload_len);
        remaining -= payload_len;
        assert(remaining >= 0);
        if (remaining > 0) {
            memmove(pipe->recv_buf->buf, pipe->recv_buf->buf + (pipe->recv_buf->len - remaining), remaining);
        }
        pipe->recv_buf->len = remaining;
        if (pipe->outer->output_cb) {
            if (pipe->outer->output_cb(pipe->outer) != _OK) {
                _LOG_E("pack output_cb failed");
                return _ERR;
            }
        }
    }
    return _OK;
}

static int unpack(sspipe_t* pipe) {
    assert(pipe);
    assert(pipe->outer);
    sspipe_ctx_t* ctx = pipe->ctx;
    uint32_t payload_len = 0;
    int remaining = 0;
    size_t cipher_len = 0;
    int pkt_len = 0;
    while (pipe->recv_buf->len > 0) {
        if (pipe->recv_buf->len < SSP_PACKET_HEAD_LEN) return _OK;
        payload_len = ntohl(*(uint32_t*)pipe->recv_buf->buf);
        if (payload_len > SSP_MAX_PAYLOAD_LEN || payload_len <= 0) {
            _LOG_E("payload_len:%d error. max_payload:%d", payload_len, SSP_MAX_PAYLOAD_LEN);
            return _ERR;
        }
        if (pipe->recv_buf->len < payload_len + SSP_PACKET_HEAD_LEN) return _OK;
        // decrypt
        if (ctx->key && ctx->iv) {
            if (crypto_decrypt(ctx->key, ctx->iv, (const unsigned char*)pipe->recv_buf->buf + SSP_PACKET_HEAD_LEN, payload_len, (unsigned char*)ctx->pkt_buf, &cipher_len) != 0) {
                _LOG_E("unpack crypto_decrypt failed");
                return _ERR;
            }
            _LOG("unpack crypto_decrypt ok.");
            assert(cipher_len == payload_len);
            pkt_len += cipher_len;
        } else {
            memcpy(ctx->pkt_buf, pipe->recv_buf->buf + SSP_PACKET_HEAD_LEN, payload_len);
            pkt_len += payload_len;
        }
        // sspipe_t* out_pipe = get_sspipe(ctx, pipe->out_id);
        // if (!out_pipe) {
        //     _LOG_E("pack get_sspipe out_id:%d failed", pipe->out_id);
        //     return _ERR;
        // }
        ssbuff_append(pipe->outer->send_buf, ctx->pkt_buf, pkt_len);
        assert(pkt_len == payload_len);
        pkt_len = 0;
        _LOG("unpack output ok.");
        remaining = pipe->recv_buf->len - (payload_len + SSP_PACKET_HEAD_LEN);
        assert(remaining >= 0);
        if (remaining > 0) {
            memmove(pipe->recv_buf->buf, pipe->recv_buf->buf + payload_len + SSP_PACKET_HEAD_LEN, remaining);
        }
        pipe->recv_buf->len = remaining;
        if (pipe->outer->output_cb) {
            if (pipe->outer->output_cb(pipe->outer) != _OK) {
                _LOG_E("unpack output_cb failed");
                return _ERR;
            }
        }
    }
    return _OK;
}

////////////////////////////////
// API
////////////////////////////////

sspipe_ctx_t* sspipe_init(struct ev_loop* loop, const char* key, int key_len, const char* iv, int iv_len, int max_pkt_buf_size) {
    sspipe_ctx_t* ctx = (sspipe_ctx_t*)calloc(1, sizeof(sspipe_ctx_t));
    if (!ctx) {
        _LOG_E("sspipe_init: calloc failed");
        return NULL;
    }
    ctx->loop = loop;
    // ctx->connect_timeout = connect_timeout;
    ctx->pipe_index = NULL;
    if (key) {
        ctx->key = (unsigned char*)calloc(1, key_len);
        if (!ctx->key) {
            _LOG_E("sspipe_init: calloc failed");
            sspipe_free(ctx);
            return NULL;
        }
        memcpy(ctx->key, key, key_len);
    }
    if (iv) {
        ctx->iv = (unsigned char*)calloc(1, iv_len);
        if (!ctx->iv) {
            _LOG_E("sspipe_init: calloc failed");
            sspipe_free(ctx);
            return NULL;
        }
        memcpy(ctx->iv, iv, iv_len);
    }
    ctx->max_pkt_buf_size = max_pkt_buf_size;
    if (max_pkt_buf_size > 0) {
        ctx->pkt_buf = (char*)calloc(1, max_pkt_buf_size);
        if (!ctx->pkt_buf) {
            _LOG_E("sspipe_init: calloc failed");
            sspipe_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

void sspipe_free(sspipe_ctx_t* ctx) {
    if (!ctx) {
        return;
    }
    if (ctx->key) {
        free(ctx->key);
        ctx->key = NULL;
    }
    if (ctx->iv) {
        free(ctx->iv);
        ctx->iv = NULL;
    }
    if (ctx->pkt_buf) {
        free(ctx->pkt_buf);
        ctx->pkt_buf = NULL;
    }
    if (ctx->pipe_index) {
        sspipe_t *pipe, *tmp;
        HASH_ITER(hh, ctx->pipe_index, pipe, tmp) {
            if (pipe->free_user_cb) pipe->free_user_cb(pipe->user);
            HASH_DEL(ctx->pipe_index, pipe);
            free_sspipe(pipe);
        }
        ctx->pipe_index = NULL;
    }
    free(ctx);
    return;
}

sspipe_t* sspipe_get(sspipe_ctx_t* ctx, int id) {
    sspipe_t* pipe = NULL;
    HASH_FIND_INT(ctx->pipe_index, &id, pipe);
    return pipe;
}

sspipe_t* sspipe_add(sspipe_ctx_t* ctx, int id, int need_pack, sspipe_output_cb_t output_cb, void* user, sspipe_free_user_cb_t free_user_cb) {
    if (!ctx || id < 0) {
        return NULL;
    }
    sspipe_t* pipe = new_sspipe(id);
    if (!pipe) {
        free_sspipe(pipe);
        return NULL;
    }
    pipe->need_pack = need_pack;
    pipe->output_cb = output_cb;
    pipe->ctx = ctx;
    pipe->user = user;
    pipe->free_user_cb = free_user_cb;
    HASH_ADD_INT(ctx->pipe_index, id, pipe);
    return pipe;
}

void sspipe_del(sspipe_t* pipe) {
    if (pipe && pipe->ctx) {
        HASH_DEL(pipe->ctx->pipe_index, pipe);
        free_sspipe(pipe);
    }
    return;
}

int sspipe_feed(sspipe_t* pipe, const char* buf, int len) {
    if (!pipe || !buf || len <= 0) {
        return _ERR;
    }
    if (ssbuff_append(pipe->recv_buf, buf, len) != _OK) {
        _LOG_E("sspipe_feed: ssbuff_append failed");
        return _ERR;
    }
    int ret = _OK;
    if (pipe->need_pack) {
        ret = pack(pipe);
    } else {
        ret = unpack(pipe);
    }
    return ret;
}

void sspipe_print_info(sspipe_ctx_t* ctx) {
    if (!ctx) {
        _LOG("sspipe_ctx is NULL");
        return;
    }
    _LOG("======== SSPIPE CTX [%p] ========", ctx);
    _LOG("Key: %s", ctx->key);
    _LOG("IV: %s", ctx->iv);
    _LOG("Packet Buffer: %d/%d bytes", ctx->pkt_buf ? strlen(ctx->pkt_buf) : 0, ctx->max_pkt_buf_size);
    _LOG("======== Connected Pipes ========");
    int sum_bytes = 0, pipe_cnt = 0;
    sspipe_t *pipe, *tmp;
    HASH_ITER(hh, ctx->pipe_index, pipe, tmp) {
        _LOG("─── Pipe ID: %d ───", pipe->id);
        _LOG("Type: %s", pipe->need_pack ? "PACKER" : "UNPACKER");
        _LOG("output_cb: %p", pipe->output_cb);
        _LOG("user: %p", pipe->user);
        _LOG("free_user_cb: %p", pipe->free_user_cb);
        _LOG("ctx: %p", pipe->ctx);
        _LOG("Recv Buffer: %d/%d bytes", pipe->recv_buf ? pipe->recv_buf->len : -1, pipe->recv_buf ? pipe->recv_buf->cap : -1);
        _LOG("Send Buffer: %d/%d bytes", pipe->send_buf ? pipe->send_buf->len : -1, pipe->send_buf ? pipe->send_buf->cap : -1);
        _LOG("Linked to: %d", pipe->outer ? pipe->outer->id : 0);
        if (pipe->recv_buf) sum_bytes += pipe->recv_buf->cap;
        if (pipe->send_buf) sum_bytes += pipe->send_buf->cap;
        pipe_cnt++;
    }
    _LOG("pipes count: %d, buffer sum: %d bytes", pipe_cnt, sum_bytes);
    if (pipe_cnt % 2 != 0) _LOG_E("invalid pipes count");
    assert(pipe_cnt % 2 == 0);
    _LOG("================================");
}
