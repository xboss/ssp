#include "sspipe.h"

#include <arpa/inet.h>
#include <sys/time.h>

typedef struct {
    int in_id;
    int out_id;
    int is_activity;
    sspipe_type_t type;
    ssbuff_t* in_buf;
    ssbuff_t* out_buf;
    sspipe_output_cb_t output_cb;
    void* user;
    ev_io* read_watcher;
    ev_io* write_watcher;
    uint64_t ctime;
    UT_hash_handle hh;
} sspipe_t;

struct sspipe_ctx_s {
    sspipe_t* pipe_index;
    unsigned char* key;
    unsigned char* iv;
    char* pkt_buf;
    int max_pkt_buf_size;
    struct ev_loop* loop;
    int connect_timeout;
};

uint64_t mstime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t millisecond = (tv.tv_sec * 1000000l + tv.tv_usec) / 1000l;
    return millisecond;
}

inline static sspipe_t* new_sspipe(int in_id) {
    sspipe_t* pipe = (sspipe_t*)calloc(1, sizeof(sspipe_t));
    if (pipe == NULL) {
        _LOG_E("new_pipe: calloc failed");
        return NULL;
    }
    pipe->in_id = in_id;
    pipe->in_buf = ssbuff_init(0);
    if (pipe->in_buf == NULL) {
        _LOG_E("new_pipe: ssbuff_init failed");
        return NULL;
    }

    pipe->out_buf = ssbuff_init(0);
    if (pipe->out_buf == NULL) {
        _LOG_E("new_pipe: ssbuff_init failed");
        return NULL;
    }
    pipe->ctime = mstime();
    return pipe;
}

inline static void free_sspipe(sspipe_ctx_t* ctx, sspipe_t* pipe) {
    if (!pipe) {
        return;
    }
    _LOG("free pipe. in_id:%d", pipe->in_id);
    if (pipe->in_buf) {
        ssbuff_free(pipe->in_buf);
        pipe->in_buf = NULL;
    }
    if (pipe->out_buf) {
        ssbuff_free(pipe->out_buf);
        pipe->out_buf = NULL;
    }
    pipe->in_id = 0;
    pipe->out_id = 0;
    if (pipe->read_watcher) {
        ev_io_stop(ctx->loop, pipe->read_watcher);
        free(pipe->read_watcher);
        pipe->read_watcher = NULL;
    }
    if (pipe->write_watcher) {
        ev_io_stop(ctx->loop, pipe->write_watcher);
        free(pipe->write_watcher);
        pipe->write_watcher = NULL;
    }
    free(pipe);
}

inline static sspipe_t* get_sspipe(sspipe_ctx_t* ctx, int in_id) {
    sspipe_t* pipe = NULL;
    HASH_FIND_INT(ctx->pipe_index, &in_id, pipe);
    return pipe;
}

static int pack(sspipe_ctx_t* ctx, sspipe_t* pipe) {
    uint32_t payload_len = 0;
    int remaining = pipe->in_buf->len;
    size_t cipher_len = 0;
    int pkt_len = 0;
    while (remaining > 0) {
        if (!get_sspipe(ctx, pipe->in_id)) {
            _LOG_E("pack get_sspipe in_id:%d failed", pipe->in_id);
            sspipe_del(ctx, pipe->out_id);
            return _ERR;
        }
        if (!get_sspipe(ctx, pipe->out_id)) {
            _LOG_E("pack get_sspipe out_id:%d failed", pipe->out_id);
            sspipe_del(ctx, pipe->in_id);
            return _ERR;
        }
        // pack and send
        payload_len = remaining > SSP_MAX_PAYLOAD_LEN ? SSP_MAX_PAYLOAD_LEN : remaining;
        uint32_t payload_len_net = htonl(payload_len);
        memcpy(ctx->pkt_buf, &payload_len_net, SSP_PACKET_HEAD_LEN);
        pkt_len += SSP_PACKET_HEAD_LEN;
        // encrypt
        if (ctx->key && ctx->iv) {
            if (crypto_encrypt(ctx->key, ctx->iv, (const unsigned char*)pipe->in_buf->buf + (pipe->in_buf->len - remaining), payload_len, (unsigned char*)ctx->pkt_buf + SSP_PACKET_HEAD_LEN,
                               &cipher_len) != 0) {
                _LOG_E("pack crypto_encrypt failed");
                return _ERR;
            }
            _LOG("pack crypto_encrypt ok.");
            assert(cipher_len == payload_len);
            pkt_len += cipher_len;
        } else {
            memcpy(ctx->pkt_buf + SSP_PACKET_HEAD_LEN, pipe->in_buf->buf + (pipe->in_buf->len - remaining), payload_len);
            pkt_len += payload_len;
        }

        sspipe_t* out_pipe = get_sspipe(ctx, pipe->out_id);
        if (!out_pipe) {
            _LOG_E("pack get_sspipe out_id:%d failed", pipe->out_id);
            return _ERR;
        }
        ssbuff_append(out_pipe->out_buf, ctx->pkt_buf, pkt_len);
        pkt_len = 0;
        _LOG("pack to target ok. payload_len:%d", payload_len);
        remaining -= payload_len;
        assert(remaining >= 0);
        if (remaining > 0) {
            memmove(pipe->in_buf->buf, pipe->in_buf->buf + (pipe->in_buf->len - remaining), remaining);
        }
        pipe->in_buf->len = remaining;
        if (out_pipe->output_cb && out_pipe->is_activity) {
            if (out_pipe->output_cb(out_pipe->in_id, out_pipe->user) != _OK) {
                _LOG_E("pack output_cb failed");
                return _ERR;
            }
        }
        if (!out_pipe->is_activity && out_pipe->ctime + ctx->connect_timeout < mstime()) {
            _LOG_E("pipe timeout");
            sspipe_unbind(ctx, out_pipe->in_id);
            return _ERR;
        }
    }
    return _OK;
}

static int unpack(sspipe_ctx_t* ctx, sspipe_t* pipe) {
    uint32_t payload_len = 0;
    int remaining = 0;
    size_t cipher_len = 0;
    int pkt_len = 0;
    while (pipe->in_buf->len > 0) {
        if (pipe->in_buf->len < SSP_PACKET_HEAD_LEN) return _OK;
        payload_len = ntohl(*(uint32_t*)pipe->in_buf->buf);
        if (payload_len > SSP_MAX_PAYLOAD_LEN || payload_len <= 0) {
            _LOG_E("payload_len:%d error. max_payload:%d", payload_len, SSP_MAX_PAYLOAD_LEN);
            return _ERR;
        }
        if (pipe->in_buf->len < payload_len + SSP_PACKET_HEAD_LEN) return _OK;
        // decrypt
        if (ctx->key && ctx->iv) {
            if (crypto_decrypt(ctx->key, ctx->iv, (const unsigned char*)pipe->in_buf->buf + SSP_PACKET_HEAD_LEN, payload_len, (unsigned char*)ctx->pkt_buf, &cipher_len) != 0) {
                _LOG_E("unpack crypto_decrypt failed");
                return _ERR;
            }
            _LOG("unpack crypto_decrypt ok.");
            assert(cipher_len == payload_len);
            pkt_len += cipher_len;
        } else {
            memcpy(ctx->pkt_buf, pipe->in_buf->buf + SSP_PACKET_HEAD_LEN, payload_len);
            pkt_len += payload_len;
        }

        sspipe_t* out_pipe = get_sspipe(ctx, pipe->out_id);
        if (!out_pipe) {
            _LOG_E("pack get_sspipe out_id:%d failed", pipe->out_id);
            return _ERR;
        }
        ssbuff_append(out_pipe->out_buf, ctx->pkt_buf, pkt_len);
        assert(pkt_len == payload_len);
        pkt_len = 0;
        _LOG("unpack output ok.");
        remaining = pipe->in_buf->len - (payload_len + SSP_PACKET_HEAD_LEN);
        assert(remaining >= 0);
        if (remaining > 0) {
            memmove(pipe->in_buf->buf, pipe->in_buf->buf + payload_len + SSP_PACKET_HEAD_LEN, remaining);
        }
        pipe->in_buf->len = remaining;

        if (out_pipe->output_cb && out_pipe->is_activity) {
            if (out_pipe->output_cb(out_pipe->in_id, out_pipe->user) != _OK) {
                _LOG_E("unpack output_cb failed");
                return _ERR;
            }
        }
        if (!out_pipe->is_activity && out_pipe->ctime + ctx->connect_timeout < mstime()) {
            _LOG_E("pipe timeout");
            sspipe_unbind(ctx, out_pipe->in_id);
            return _ERR;
        }
    }
    return _OK;
}

////////////////////////////////
// API
////////////////////////////////

int sspipe_new(sspipe_ctx_t* ctx, int in_id, sspipe_type_t type, int is_activity, sspipe_output_cb_t output_cb, void* user) {
    if (!ctx || in_id < 0) {
        return _ERR;
    }
    sspipe_t* pipe = new_sspipe(in_id);
    if (!pipe) {
        free_sspipe(ctx, pipe);
        return _ERR;
    }
    pipe->type = type;
    pipe->output_cb = output_cb;
    pipe->user = user;
    pipe->is_activity = is_activity;
    pipe->read_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!pipe->read_watcher) {
        free_sspipe(ctx, pipe);
        return _ERR;
    }
    pipe->write_watcher = (ev_io*)calloc(1, sizeof(ev_io));
    if (!pipe->write_watcher) {
        free_sspipe(ctx, pipe);
        return _ERR;
    }
    HASH_ADD_INT(ctx->pipe_index, in_id, pipe);
    return _OK;
}

ev_io* sspipe_get_read_watcher(sspipe_ctx_t* ctx, int in_id) {
    sspipe_t* pipe = get_sspipe(ctx, in_id);
    if (!pipe) return NULL;
    return pipe->read_watcher;
}

ev_io* sspipe_get_write_watcher(sspipe_ctx_t* ctx, int in_id) {
    sspipe_t* pipe = get_sspipe(ctx, in_id);
    if (!pipe) return NULL;
    return pipe->write_watcher;
}

// int sspipe_join(sspipe_ctx_t* ctx, int in_id, int out_id, sspipe_type_t type, sspipe_output_cb_t output_cb, void* user) {
//     sspipe_t* pipe = NULL;
//     HASH_FIND_INT(ctx->pipe_index, &in_id, pipe);
//     if (!pipe) {
//         return _ERR;
//     }
//     pipe->out_id = out_id;
//     pipe->output_cb = output_cb;
//     pipe->user = user;
//     pipe->type = type;
//     return _OK;
// }

void sspipe_del(sspipe_ctx_t* ctx, int in_id) {
    sspipe_t* pipe = get_sspipe(ctx, in_id);
    if (pipe) {
        HASH_DEL(ctx->pipe_index, pipe);
        free_sspipe(ctx, pipe);
    }
    return;
}

int sspipe_bind(sspipe_ctx_t* ctx, int in_id, int out_id) {
    sspipe_t* pipe0 = get_sspipe(ctx, in_id);
    sspipe_t* pipe1 = get_sspipe(ctx, out_id);
    assert((pipe0 && pipe1) || (!pipe0 && !pipe1));
    if (!pipe0) {
        _LOG_E("sspipe_bind: in_id:%d not found", in_id);
        return _ERR;
    }
    if (!pipe1) {
        _LOG_E("sspipe_bind: out_id:%d not found", out_id);
        return _ERR;
    }
    pipe0->out_id = pipe1->in_id;
    pipe1->out_id = pipe0->in_id;
    return _OK;
}
int sspipe_unbind(sspipe_ctx_t* ctx, int in_id) {
    sspipe_t* pipe0 = get_sspipe(ctx, in_id);
    if (!pipe0) {
        _LOG_E("sspipe_unbind: in_id:%d not found", in_id);
        return _ERR;
    }
    int out_id = pipe0->out_id;
    sspipe_del(ctx, pipe0->in_id);
    sspipe_t* pipe1 = get_sspipe(ctx, out_id);
    if (!pipe1) {
        _LOG_E("sspipe_unbind: out_id:%d not found", out_id);
        return _ERR;
    }
    sspipe_del(ctx, pipe1->in_id);
    return _OK;
}

int sspipe_is_activity(sspipe_ctx_t* ctx, int in_id) {
    sspipe_t* pipe = get_sspipe(ctx, in_id);
    if (!pipe) return 0;
    return pipe->is_activity;
}

int sspipe_set_activity(sspipe_ctx_t* ctx, int in_id, int is_activity) {
    sspipe_t* pipe = get_sspipe(ctx, in_id);
    if (!pipe) return _ERR;
    pipe->is_activity = 1;
    return _OK;
}

int sspipe_feed(sspipe_ctx_t* ctx, int in_id, const char* buf, int len) {
    sspipe_t* pipe = get_sspipe(ctx, in_id);
    if (!pipe) {
        _LOG_E("sspipe_feed: pipe not found, id:%d", in_id);
        return _ERR;
    }
    if (ssbuff_append(pipe->in_buf, buf, len) != _OK) {
        _LOG_E("sspipe_feed: ssbuff_append failed");
        return _ERR;
    }

    // if (!pipe->is_activity) {
    //     if (pipe->ctime + ctx->connect_timeout < mstime()) {
    //         _LOG_E("pipe timeout id:%d", pipe->in_id);
    //         sspipe_unbind(ctx, pipe->in_id);
    //         return _ERR;
    //     }
    //     return _OK;
    // }

    int ret = _OK;
    if (pipe->type == SSPIPE_TYPE_UNPACK) {
        ret = unpack(ctx, pipe);
    } else if (pipe->type == SSPIPE_TYPE_PACK) {
        ret = pack(ctx, pipe);
    } else {
        _LOG_E("sspipe_feed: unknown type");
        return _ERR;
    }
    return ret;
}

ssbuff_t* sspipe_take(sspipe_ctx_t* ctx, int id) {
    sspipe_t* pipe = get_sspipe(ctx, id);
    if (!pipe) {
        _LOG_E("sspipe_feed: pipe not found, id:%d", id);
        return NULL;
    }
    assert(pipe->out_buf);
    return pipe->out_buf;
}

sspipe_ctx_t* sspipe_init(struct ev_loop* loop, const char* key, int key_len, const char* iv, int iv_len, int connect_timeout, int max_pkt_buf_size) {
    sspipe_ctx_t* ctx = (sspipe_ctx_t*)calloc(1, sizeof(sspipe_ctx_t));
    if (!ctx) {
        _LOG_E("sspipe_init: calloc failed");
        return NULL;
    }
    ctx->loop = loop;
    ctx->connect_timeout = connect_timeout;
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
            HASH_DEL(ctx->pipe_index, pipe);
            free_sspipe(ctx, pipe);
        }
        ctx->pipe_index = NULL;
    }
    free(ctx);
    return;
}
