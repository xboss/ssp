#include "ring_buf.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _OK 0
#define _ERR -1

#ifndef _ALLOC
#define _ALLOC(_p, _type, _size)   \
    (_p) = (_type)malloc((_size)); \
    if (!(_p)) {                   \
        perror("alloc error");     \
        exit(1);                   \
    }
#endif

#define _REMAIN_LEN(_rb) (_rb->capacity - _rb->size)

struct ring_buf_s {
    char* buf;
    int size, capacity, head, tail;
};

ring_buf_t* ring_buf_init(int capacity) {
    if (capacity <= 0) {
        return NULL;
    }
    ring_buf_t* _ALLOC(rb, ring_buf_t*, sizeof(ring_buf_t));
    memset(rb, 0, sizeof(ring_buf_t));
    rb->capacity = capacity;
    _ALLOC(rb->buf, char*, capacity);
    memset(rb->buf, 0, capacity);
    return rb;
}

void ring_buf_free(ring_buf_t* rb) {
    /* TODO: */
    return;
}

int ring_buf_size(ring_buf_t* rb) {
    if (!rb) return _ERR;
    return rb->size;
}

inline static int shift(int pos, int offset, int cap) {
    return (pos + offset) % cap;
}

/* inline static int is_full(ring_buf_t* rb) {
    return shift(rb->tail, 1, rb->capacity) + 1 == rb->head;
} */

int ringbuf_push(ring_buf_t* rb, char* buf, int len) {
    if (!rb || !buf || len <= 0 || len > _REMAIN_LEN(rb)) return _ERR;
    if (rb->tail + len <= rb->capacity) {
        memcpy(rb->buf + rb->tail, buf, len);
    } else {
        int tmp_len = (rb->capacity - rb->tail);
        memcpy(rb->buf + rb->tail, buf, tmp_len);
        memcpy(rb->buf, buf + tmp_len, len - tmp_len);
    }
    rb->size += len;
    shift(rb->tail, len, rb->capacity);
    return _OK;
}

#define _MIN(a, b) ((a) >= (b) ? (b) : (a))
int ringbuf_pop(ring_buf_t* rb, int idx, char* out, int len) {
    if (!rb || len <= 0 || rb->size <= 0) return _ERR;
    int rdlen = _MIN(len, rb->size);
    if (rb->head + len <= rb->capacity) {
        memcpy(out, rb->buf + rb->head, rdlen);
        return rdlen;
    }
    int tmp_len = (rb->capacity - rb->head);
    memcpy(out, rb->buf + rb->head, tmp_len);
    memcpy(out + tmp_len, rb->buf + rb->head + tmp_len, len - tmp_len);
    /* TODO: */
    return;
}

char* ringbuf_take(ring_buf_t* rb, int idx, int* len) {
    /* TODO: */
    return;
}

/* test */
int main(int argc, char const* argv[]) {
    ring_buf_t* rb = ring_buf_init(10);
    printf("size:%d\n", ring_buf_size(rb));
    ring_buf_free(rb);
    return 0;
}
