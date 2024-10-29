#ifndef _STREAM_BUF_H
#define _STREAM_BUF_H

typedef struct stream_buf_s stream_buf_t;

stream_buf_t *sb_init(const char *buf, int len);
void sb_free(stream_buf_t *sb);

int sb_read_all(stream_buf_t *sb, char *out, int len);
int sb_write(stream_buf_t *sb, const char *buf, int len);
int sb_get_size(stream_buf_t *sb);
/* char *sb_sub(stream_buf_t *sb, int start, int len); */

#endif /* STREAM_BUF_H */