#ifndef _RING_BUF_H
#define _RING_BUF_H

typedef struct ring_buf_s ring_buf_t;

ring_buf_t *ring_buf_init(int capacity);
void ring_buf_free(ring_buf_t *rb);
int ring_buf_size(ring_buf_t *rb);
int ringbuf_push(ring_buf_t *rb, char *buf, int len);
char *ringbuf_pop(ring_buf_t *rb, int idx, int *len);
char *ringbuf_take(ring_buf_t *rb, int idx, int *len);

#endif /* RING_BUF_H */