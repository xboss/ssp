#include "sspipe.h"

sspipe_t* g_pipe_index = NULL;

// int sspipe_init() {
//     /* TODO: */
//     return _OK;
// }

static sspipe_t* new_sspipe(int in_id) {
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
    return pipe;
}

static void free_sspipe(sspipe_t* pipe) {
    if (!pipe) {
        return;
    }
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
    free(pipe);
}

static sspipe_t* get_sspipe(int in_id) {
    sspipe_t* pipe = NULL;
    HASH_FIND_INT(g_pipe_index, &in_id, pipe);
    return pipe;
}

////////////////////////////////
// API
////////////////////////////////

int sspipe_new(int in_id, int out_id, sspipe_output_cb_t output_cb, void* user) {
    if (in_id == out_id || in_id < 0) {
        return _ERR;
    }
    sspipe_t* pipe = new_sspipe(in_id);
    if (!pipe) {
        free_sspipe(pipe);
        return _ERR;
    }
    pipe->output_cb = output_cb;
    pipe->user = user;
    if (out_id > 0) {
        pipe->out_id = out_id;
        pipe = new_sspipe(out_id);
        if (!pipe) {
            free_sspipe(pipe);
            return _ERR;
        }
        pipe->out_id = in_id;
        pipe->output_cb = output_cb;
        pipe->user = user;
    }
    return _OK;
}

int sspipe_join(int in_id, int out_id, sspipe_output_cb_t output_cb, void* user) {
    sspipe_t* pipe = NULL;
    HASH_FIND_INT(g_pipe_index, &in_id, pipe);
    if (!pipe) {
        return _ERR;
    }
    pipe->out_id = out_id;
    pipe->output_cb = output_cb;
    pipe->user = user;
    return _OK;
}

int sspipe_feed(int in_id, const char* buf, int len) {
    sspipe_t* pipe = get_sspipe(in_id);
    if (!pipe) {
        _LOG_E("sspipe_feed: pipe not found");
        return _ERR;
    }
    if (ssbuff_append(pipe->in_buf, buf, len) != _OK) {
        _LOG_E("sspipe_feed: ssbuff_append failed");
        return _ERR;
    }

    /* TODO: */
    return _OK;
}

void sspipe_del(int in_id) {
    sspipe_t* pipe = NULL;
    HASH_FIND_INT(g_pipe_index, &in_id, pipe);
    if (pipe) {
        HASH_DEL(g_pipe_index, pipe);
        free_sspipe(pipe);
    }
    return;
}

// void sspipe_free() {
//     /* TODO: */
//     return;
// }
