#include "stream_buf.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- stream buffer ---------- */

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)        \
    _type(_p) = (_type)malloc((_size)); \
    if (!(_p)) {                        \
        perror("alloc error");          \
        exit(1);                        \
    }
#endif

#define DEF_SB_BLOCK_SZ 1024
#define SB_REMAIN_POS (DEF_SB_BLOCK_SZ - sb->space_sz)

typedef struct sb_block_s {
    char buf[DEF_SB_BLOCK_SZ];
    /* int sz; */
    struct sb_block_s *next;
} sb_block_t;

struct stream_buf_s {
    sb_block_t *head;
    sb_block_t *tail;
    int block_cnt;
    int sum_buf_sz;
    int space_sz;
};

static int add_block(stream_buf_t *sb, const char *buf, int len) {
    _ALLOC(block, sb_block_t *, sizeof(sb_block_t));
    memset(block, 0, sizeof(sb_block_t));
    int wlen = len;
    if (len > DEF_SB_BLOCK_SZ) {
        wlen = DEF_SB_BLOCK_SZ;
    }
    memcpy(block->buf, buf, wlen);
    sb->tail->next = block;
    sb->tail = sb->tail->next;
    sb->block_cnt++;
    sb->sum_buf_sz += wlen;
    if (wlen == DEF_SB_BLOCK_SZ) {
        sb->space_sz = 0;
    } else {
        sb->space_sz = DEF_SB_BLOCK_SZ - wlen;
    }
    return wlen;
}

int sb_get_size(stream_buf_t *sb) {
    if (!sb) return 0;
    return sb->sum_buf_sz;
}

int sb_read_all(stream_buf_t *sb, char *out, int len) {
    if (!sb || !out || len <= 0 || sb->sum_buf_sz <= 0 || len < sb->sum_buf_sz) return 0;
    int out_len = sb->sum_buf_sz;
    sb_block_t *blk;
    int i, rlen, b_cnt = sb->block_cnt;
    for (i = 0; i < b_cnt; i++) {
        blk = sb->head;
        rlen = DEF_SB_BLOCK_SZ;
        if (i == b_cnt - 1) {
            rlen = DEF_SB_BLOCK_SZ - sb->space_sz;
        }
        memcpy(out + i * DEF_SB_BLOCK_SZ, blk->buf, rlen);
        if (i < b_cnt - 1) {
            sb->head = sb->head->next;
            free(blk);
            sb->block_cnt--;
        }
        sb->sum_buf_sz -= rlen;
    }
    assert(sb->sum_buf_sz == 0);
    assert(sb->block_cnt == 1);
    assert(sb->head == sb->tail);
    sb->space_sz = DEF_SB_BLOCK_SZ;
    return out_len;
}

/* char *sb_read(stream_buf_t *sb, int *out_len) {
    if (!sb || !out_len || sb->sum_buf_sz <= 0) return NULL;
    _ALLOC(buf, char *, sb->sum_buf_sz);
    *out_len = sb->sum_buf_sz;
    sb_block_t *blk;
    int i, rlen, b_cnt = sb->block_cnt;
    for (i = 0; i < b_cnt; i++) {
        blk = sb->head;
        rlen = DEF_SB_BLOCK_SZ;
        if (i == b_cnt - 1) {
            rlen = DEF_SB_BLOCK_SZ - sb->space_sz;
        }
        memcpy(buf + i * DEF_SB_BLOCK_SZ, blk->buf, rlen);
        if (i < b_cnt - 1) {
            sb->head = sb->head->next;
            free(blk);
            sb->block_cnt--;
        }
        sb->sum_buf_sz -= rlen;
    }
    assert(sb->sum_buf_sz == 0);
    assert(sb->block_cnt == 1);
    assert(sb->head == sb->tail);
    sb->space_sz = DEF_SB_BLOCK_SZ;
    return buf;
} */

int sb_write(stream_buf_t *sb, const char *buf, int len) {
    if (!sb || !buf || len <= 0) return _ERR;
    if (len <= sb->space_sz) {
        memcpy(sb->tail->buf + SB_REMAIN_POS, buf, len);
        sb->space_sz -= len;
        sb->sum_buf_sz += len;
        return _OK;
    }
    if (sb->space_sz > 0) {
        memcpy(sb->tail->buf + SB_REMAIN_POS, buf, sb->space_sz);
        buf += sb->space_sz;
        len -= sb->space_sz;
        sb->sum_buf_sz += sb->space_sz;
        sb->space_sz = 0;
    }
    int b_cnt = len / DEF_SB_BLOCK_SZ;
    if (len % DEF_SB_BLOCK_SZ != 0) b_cnt++;
    int i, wlen = 0;
    for (i = 0; i < b_cnt; i++) {
        wlen = add_block(sb, buf, len);
        buf += wlen;
        len -= wlen;
    }
    return _OK;
}

void sb_free(stream_buf_t *sb) {
    if (!sb) return;
    sb_block_t *blk;
    int i;
    for (i = 0; i < sb->block_cnt; i++) {
        blk = sb->head;
        sb->head = sb->head->next;
        free(blk);
    }
    free(sb);
}

stream_buf_t *sb_init(const char *buf, int len) {
    _ALLOC(sb, stream_buf_t *, sizeof(stream_buf_t));
    memset(sb, 0, sizeof(stream_buf_t));
    _ALLOC(block, sb_block_t *, sizeof(sb_block_t));
    memset(block, 0, sizeof(sb_block_t));
    sb->head = block;
    sb->tail = block;
    sb->block_cnt = 1;
    sb->space_sz = DEF_SB_BLOCK_SZ;
    if (buf && len >= 0) {
        if (sb_write(sb, buf, len) != _OK) {
            sb_free(sb);
            return NULL;
        }
    }
    return sb;
}
