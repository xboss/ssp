#ifndef _SSPIPE_H
#define _SSPIPE_H

#include "ss.h"

typedef enum { SSPIPE_TYPE_UNPACK = 0, SSPIPE_TYPE_PACK } SSPIPE_TYPE;
typedef int (*sspipe_output_cb_t)(const char* buf, int len, int id, void* user);

typedef struct {
    int in_id;
    int out_id;
    ssbuff_t* in_buf;
    ssbuff_t* out_buf;
    sspipe_output_cb_t output_cb;
    void* user;
    UT_hash_handle hh;
} sspipe_t;

// int sspipe_init();
int sspipe_new(int in_id, int out_id, sspipe_output_cb_t output_cb, void* user);
int sspipe_join(int in_id, int out_id, sspipe_output_cb_t output_cb, void* user);
void sspipe_del(int in_id);
int sspipe_feed(int in_id, const char* buf, int len);
// int sspipe_take(int in_id, ssbuff_t* out_buf);
// void sspipe_free();

#endif /* _SSPIPE_H */